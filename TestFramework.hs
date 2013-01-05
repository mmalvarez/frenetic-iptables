--Defines data structures and functions for a framework
--For use in testing FreneTables by simulating its operation on "fake" packet data structures

import Pred2.hs as P

--Simulates a packet - model relevant information from pkt header
--Source IP, Dest IP, Protocol, Source port, Dest port
data SimPacket =
  SimPacket IPRange IPRange Int Int Int

--The outcome of evaluation on a packet. List the chain, along with whether it was accepted, dropped, or reaches the end of the chain.
data SimOutcome = Accept | Drop | Default

data SimReport = SimReport Chain SimOutcome SimPacket

--Interpret Logic. Simulate compiler output on a packet.
simulatePacket :: CompileState -> SimPacket -> SimReport
simulatePacket state pkt =
  
