module Pred where


--Defines data structures and functions for manipulating predicates
import           Control.Applicative
import           Data.IP

--Data structure syntactically equivalent to iptables rules output
--2 outputs from each node - action and "falling off" - capture this
--automata
--recursive translation - think about invariants

--Fields for IP matching
--data Field = Srcip | Dstip
data Pred =
    Srcip IPRange    --Match on source IP
    | Dstip IPRange    --Match on dest IP
    | Protocol Int     --Match on protocol field
    | Srcport Int      --Match on source port, for connection-oriented packets
    | Dstport Int      --Match on destination port
    --logically combining predicates
    | Neg Pred
    | AND Pred Pred
    | OR Pred Pred
    | Always
    | Never

data Action = Accept | Drop
flipAction :: Action -> Action
flipAction Accept = Drop
flipAction Drop = Accept

data Rule = Rule Pred Action

--Structures representing the overall system
--Convention: when we get to the end of a chain, DROP.
--newtype Chain = [Rule]

--data Table = Filter [Chain] | NAT [Chain] | Mangle [Chain]

--Translating structures into output
translateAction :: Action -> String
translateAction Accept = "ACCEPT"
translateAction Drop = "DROP"

--Combine two rules
--Insert a string between two other strings
between :: String -> String -> String -> String
between b a c = a ++ b ++ c

translateRules :: [Rule] -> String
translateRules =
  foldl combine ""
  where combine = flip $ between "\n" . translateRule

--Processing predicates into IPTables
--TODO - support different tables
translateRule :: Rule -> String
translateRule (Rule (Srcip range) a)  =
  "iptables -A INPUT -s " ++ show range ++ " " ++ translateAction a

translateRule (Rule (Dstip range) a) =
  "iptables -A INPUT -d " ++ show range ++ " " ++ translateAction a

--TODO - support protocol "all"?
translateRule (Rule (Protocol prot) a) =
  "iptables -A INPUT -p " ++ show prot ++ " " ++ translateAction a

translateRule (Rule (Srcport port) a) =
  "iptables -A INPUT --sports " ++ show port ++ " " ++ translateAction a

translateRule (Rule (Dstport port) a) =
  "iptables -A INPUT --dports " ++ show port ++ " " ++ translateAction a

translateRule (Rule Always a) =
  "iptables -A INPUT " ++ translateAction a

translateRule (Rule Never a) =
  "iptables -A INPUT " ++ translateAction (flipAction a)

--Combinators
--Todo - implement chaining better?
translateRule (Rule (OR p q) a) =
  between "\n" (translateRule (Rule p a)) (translateRule (Rule q a))

--Probably there's a better way.
--translateRule (Rule (AND p q) a) =
--  translateRules $ [Rule (Not p) (flipAction a), Rule (Not q (flipAction a)), Rule  ]
translateRule (Rule (AND p q) a) =
  notString ++ "\n" ++ translateRule (Rule Always a)

translateRule (Rule (AND p q) a) =
  notString ++ "\n" ++ translateRule (Rule Always a)
  where notString =
          between "\n" (translateRule (Rule (Neg p) a)) (translateRule (Rule (Neg q) a))

--Negation
translateRule (Rule (Neg (Srcip range)) a) =
  "iptables -A INPUT !-s " ++ show range ++ " " ++ translateAction a

translateRule (Rule (Neg (Dstip range)) a) =
  "iptables -A INPUT !-d " ++ show range ++ " " ++ translateAction a

translateRule (Rule (Neg (Protocol prot)) a) =
  "iptables -A INPUT !-p " ++ show prot ++ " " ++ translateAction a

translateRule (Rule (Neg (Srcport port)) a) =
  "iptables -A INPUT !--sports " ++ show port ++ " " ++ translateAction a

translateRule (Rule (Neg (Dstport port)) a) =
  "iptables -A INPUT !--dports " ++ show port ++ " " ++ translateAction a

translateRule (Rule (Neg (Neg p)) a) =
  translateRule (Rule p a)

--Combinators
--Need to rethink this logic.
--De Morgan's law
translateRule (Rule (Neg (OR p q)) a) =
  translateRule $ Rule (AND (Neg p) (Neg q)) a

translateRule (Rule (Neg (AND p q)) a) =
  notString ++ "\n" ++ translateRule (Rule Always (flipAction a))
  where notString =
          between "\n" (translateRule (Rule (Neg p) a)) (translateRule (Rule (Neg q) a))

translateRule (Rule (Neg (Always)) a) =
  translateRule $ Rule Never a

translateRule (Rule (Neg (Never)) a) =
  translateRule $ Rule Always a


--We need to support the idea of chains for these.
--translateRule (Rule (AND p q) a) =
--translateRule (Rule (OR p q) a) =
