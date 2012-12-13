Module Token where

---Stores syntactic output tokens

--Tokens are options to the iptables command

--A command consists of target, chain, rule, a predicate, and an action
data Command = Command Chain PredToken Action

data Chain = Input | Output

data Action = Accept | Drop

data PredToken =
  Srcip IPRange
  | NotSrcip IPRange
  | Dstip IPRange
  | NotDstip IPRange
  | Protocol Int
  | NotProtocol Int
  | Srcport Int
  | NotSrcport Int
  | Dstport Int
  | NotDstport Int
  | Always

translateCommand :: Command -> String
translateCommand (Command chain pred action) =
  "iptables -A " ++ chainS ++ " " ++ predS ++ " " ++ actionS ++ "\n"
  where
    chainS = case chain of
      Input -> "INPUT"
      Output -> "OUTPUT"

    predS = case pred of
      (Srcip range) -> "-s " ++ show range
      (NotSrcip range) -> "!-s " ++ show range
      (Dstip range) -> "-d " ++ show range
      (NotDstip range) -> "!-d " ++ show range
      (Protocol prot) -> "-p " ++ show prot
      (NotProtocol prot) -> "!-p " ++ show prot
      (Srcport port) -> "--sports " ++ show port
      (NotSrcport port) -> "!--sports " ++ show port
      (Dstport port) -> "--dports " ++ show port
      (NotDstport port) -> "!--dports " ++ show port
      (Always) -> ""

    actionS = case Action of
      Accept -> "ACCEPT"
      Drop -> "DROP"
