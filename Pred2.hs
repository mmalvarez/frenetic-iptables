module Pred2 where

--Defines data structures and functions for manipulating predicates
import           Control.Applicative
import           Data.IP

--Data structure syntactically equivalent to iptables rules output
--2 outputs from each node - action and "falling off" - capture this
--automata
--recursive translation - think about invariants

--Keep track of chains
type ChainNum = Int

--
type CompileState = State ChainNum [Command]

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

flipAction :: Action -> Action
flipAction Accept = Drop
flipAction Drop = Accept
flipAction (ToChain n) = (ToChain n)      --This one shouldn't happen

data Rule = Rule Pred Action

--Structures representing the overall system
--Convention: when we get to the end of a chain, DROP.
--newtype Chain = [Rule]

--data Table = Filter [Chain] | NAT [Chain] | Mangle [Chain]

--Translate a list of rules to list of commands
translateRules :: [Rule] -> [Command]
translateRules =
  concat . map translateRule

--translate a single rule
translateRule :: Rule -> Chain -> CompileState

--handle combinators
translateRule (Rule (OR p1 p2) action) chain  =  do
  res1 <- translateRule (Rule p1 action) chain
  res2 <- translateRule (Rule p2 action) chain
  return $ res1 ++ res2

--AND is a tricky case - we need two user-chains, so we add 2 to state
--TODO: make it drop if it goes off the end of the user chain
translateRule (Rule (AND p1 p2) action) chain =  do
  --create chain 1
  createChain1@(User n1) <- CreateChain $ get
  modify (+1)
  --create chain 2
  createChain2@(User n2) <- CreateChain $ get
  modify (+1)
  --create jump to chain 1
  jump1 <- Junction chain Always $ ToChain n1
  --link action into chain 1
  res1 <- translateRule (Rule p1 action) $ User n1
  --create jump from chain 1 to chain 2
  jump2 <- Junction (User n1) Always $ User n1
  --link action into chain 2
  res2 <- translateRule (Rule p2 action) $ User n2
  --string together
  return $ createChain1 ++ createChain2 ++ jump1 ++ res1 ++
    jump2 ++ res2

translateRule (Rule (Neg p) action) chain = \s ->
  case p of
    Neg p -> translateRule s (Rule p action)

    --Invert combinators - DeMorgan's laws
    AND p q -> translateRule s $ Rule (OR  (Neg p) (Neg q))
    OR  p q -> translateRele s $ Rule (AND (Neg p) (Neg q))

    otherwise ->
      --invert primitives
      State s [Junction Input negatedRules action]
      where negatedRules = case p of
              Srcip ipr -> NotSrcip ipr
              NotSrcip ipr -> Srcip ipr
              Dstip ipr -> NotDstip ipr
              NotDstip ipr -> Dstip ipr
              Protocol prot -> NotProtocol prot
              NotProtocol prot -> Protocol prot
              Srcport port -> NotSrcport port
              NotSrcport port -> Srcport port
              Dstport port -> NotDstport port
              NotDstport prot -> Dstport port

--otherwise, just translate the primitive
translateRule (Rule primitive action) = \s ->
  State s [Junction Input translatedPrimitive action]
  where translatedPrimitive = case primitive of
          Srcip ipr -> Srcip ipr
          Dstip ipr -> Dstip ipr
          Protocol prot -> Protocol prot
          Srcport port -> Srcport port
          Dstport port -> Dstport port

{--
--combinators
translateRule (Rule (Neg pred) action) =
  [Command Input negpred action]
  where negpred = case pred of
          Srcip range -> NotSrcip range
          Dstip range -> NotDstip range
          Protocol prot -> NotProtocol prot
          Srcport port -> NotSrcport port
          DstPort port -> NotDstport port
          Always ->

                  --AND OR Neg Always Never
--}
{--
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
nn
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
--}
