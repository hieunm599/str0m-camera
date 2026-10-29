//! Exclusive CPU accounting inside sampled synchronous actor polls.
#![allow(missing_docs)]
use std::{cell::RefCell, marker::PhantomData, rc::Rc};
pub const N:usize=24;
#[derive(Clone,Copy,Debug)]
#[repr(usize)]
pub enum Phase { Other, Output, Srtp, Srtcp, Timeout, Send, VideoWrite, AudioWrite, Receive, Packetize, RtpBuild, Network }
pub const NAMES:[&str;N]=["other","rtc_output_other","srtp_rtp","srtp_rtcp","rtc_timeout","udp_send","video_write","audio_write","receive","packetize","rtp_build","network_progress",
 "audio_srtp_other","audio_srtp_prepare","audio_srtp_allocate","audio_srtp_copy","audio_srtp_aead","audio_srtp_provider_other",
 "video_srtp_other","video_srtp_prepare","video_srtp_allocate","video_srtp_copy","video_srtp_aead","video_srtp_provider_other"];
#[derive(Clone,Copy,Debug)]
pub struct Ledger {pub cpu:[u64;N],pub calls:[u64;N],pub bytes:[u64;N],pub valid:bool}
impl Default for Ledger {fn default()->Self{Self{cpu:[0;N],calls:[0;N],bytes:[0;N],valid:true}}}
struct State {clock:fn()->Option<u64>,last:Option<u64>,phase:usize,depth:usize,media:Option<bool>,ledger:Ledger}
impl State {
 fn edge(&mut self) {
  let now=(self.clock)();
  match now.zip(self.last).and_then(|(n,l)|n.checked_sub(l)) {Some(d)=>self.ledger.cpu[self.phase]+=d,None=>self.ledger.valid=false}
  self.last=now;
 }
}
thread_local! {static ACTIVE:RefCell<Option<State>>=const{RefCell::new(None)};}
pub struct Context {owned:bool,_local:PhantomData<Rc<()>>}
impl Context {
 pub fn begin(clock:fn()->Option<u64>)->Self {
  let owned=ACTIVE.with(|cell|{
   let mut s=cell.borrow_mut();
   if let Some(state)=s.as_mut(){state.ledger.valid=false;return false;}
   let last=clock();*s=Some(State{clock,last,phase:0,depth:0,media:None,ledger:Ledger{valid:last.is_some(),..Ledger::default()}});true
  });Self{owned,_local:PhantomData}
 }
 pub fn finish(mut self)->Ledger {
  if !self.owned{return Ledger{valid:false,..Ledger::default()};}
  let result=ACTIVE.with(|cell|{
   let mut state=cell.borrow_mut().take().unwrap();state.edge();
   state.ledger.valid &= state.depth==0;state.ledger
  });self.owned=false;result
 }
}
impl Drop for Context {fn drop(&mut self){if self.owned{ACTIVE.with(|c|{c.borrow_mut().take();});}}}
pub struct Span {previous:usize,phase:usize,depth:usize,active:bool,_local:PhantomData<Rc<()>>}
#[derive(Clone,Copy)]
#[repr(usize)]
pub enum GcmStage { Other, Prepare, Allocate, Copy, Aead, Provider }
/// Scope negotiated media identity around synchronous SRTP protection only.
pub fn with_media<T>(audio:bool,f:impl FnOnce()->T)->T {
 struct Restore(Option<bool>);
 impl Drop for Restore {fn drop(&mut self){ACTIVE.with(|c|{if let Some(s)=c.borrow_mut().as_mut(){s.media=self.0;}});}}
 let previous=ACTIVE.with(|c|c.borrow_mut().as_mut().map(|s|{let p=s.media;s.media=Some(audio);p}));
 let _restore=previous.map(Restore);f()
}
impl Span {
 pub fn new(phase:Phase,bytes:usize)->Self {Self::index(phase as usize,bytes)}
 pub fn gcm(stage:GcmStage,bytes:usize)->Self {
  let phase=ACTIVE.with(|c|c.borrow().as_ref().and_then(|s|s.media).map(|audio|if audio{12}else{18}));
  match phase {Some(base)=>Self::index(base+stage as usize,bytes),None=>Self{previous:0,phase:0,depth:0,active:false,_local:PhantomData}}
 }
 fn index(phase:usize,bytes:usize)->Self {
  ACTIVE.with(|cell|{
   let mut s=cell.borrow_mut();
   let Some(s)=s.as_mut() else{return Self{previous:0,phase:0,depth:0,active:false,_local:PhantomData};};
   s.edge();let previous=s.phase;s.phase=phase;s.depth+=1;s.ledger.calls[s.phase]+=1;s.ledger.bytes[s.phase]+=bytes as u64;
   Self{previous,phase:s.phase,depth:s.depth,active:true,_local:PhantomData}
  })
 }
}
impl Drop for Span {
 fn drop(&mut self){if !self.active{return;}
  ACTIVE.with(|cell|{if let Some(s)=cell.borrow_mut().as_mut(){s.edge();s.ledger.valid &= s.depth==self.depth && s.phase==self.phase;s.phase=self.previous;s.depth=s.depth.saturating_sub(1);}});
 }
}
#[cfg(test)]mod tests {
 use super::*;use std::cell::Cell;
 thread_local! {static TIME:Cell<u64>=const{Cell::new(0)};}
 fn clock()->Option<u64>{Some(TIME.with(|t|t.get()))}
 fn advance(n:u64){TIME.with(|t|t.set(t.get()+n));}
 #[test]fn exclusive_nested_and_inactive(){
  let inactive=Span::new(Phase::Srtp,1);drop(inactive);
  let c=Context::begin(clock);advance(2);
  {let _o=Span::new(Phase::Output,0);advance(3);{let _s=Span::new(Phase::Srtp,99);advance(7);}advance(5);}
  advance(11);let l=c.finish();assert!(l.valid);assert_eq!(l.cpu[0],13);assert_eq!(l.cpu[1],8);assert_eq!(l.cpu[2],7);assert_eq!(l.cpu.iter().sum::<u64>(),28);assert_eq!(l.bytes[2],99);
 }
 #[test]fn failure_and_context_cleanup(){
  let c=Context::begin(||None);assert!(!c.finish().valid);
  {let _c=Context::begin(clock);let nested=Context::begin(clock);assert!(!nested.finish().valid);}
  let c=Context::begin(clock);assert!(c.finish().valid);
 }
 #[test]fn out_of_order_span_rejected(){let c=Context::begin(clock);let a=Span::new(Phase::Output,0);let b=Span::new(Phase::Srtp,0);drop(a);drop(b);assert!(!c.finish().valid);}
 #[test]fn media_children_conserve_and_restore(){
  let c=Context::begin(clock);
  with_media(false,||{
   let _p=Span::gcm(GcmStage::Other,1000);advance(2);
   {let _a=Span::gcm(GcmStage::Allocate,1016);advance(3);}
   {let _p=Span::gcm(GcmStage::Provider,1000);advance(5);
    {let _c=Span::gcm(GcmStage::Copy,1000);advance(7);}
    {let _c=Span::gcm(GcmStage::Aead,1000);advance(11);}}
   with_media(true,||{let _a=Span::gcm(GcmStage::Other,20);advance(13);});
   {let _a=Span::gcm(GcmStage::Prepare,0);advance(17);}
  });
  {let _s=Span::new(Phase::Srtp,1);advance(19);}
  let l=c.finish();assert!(l.valid);assert_eq!(l.cpu.iter().sum::<u64>(),77);
  assert_eq!(l.cpu[18],2);assert_eq!(l.cpu[20],3);assert_eq!(l.cpu[23],5);
  assert_eq!(l.cpu[21],7);assert_eq!(l.cpu[22],11);assert_eq!(l.cpu[12],13);
  assert_eq!(l.cpu[19],17);assert_eq!(l.cpu[2],19);assert_eq!(l.bytes[18],1000);
 }

}
