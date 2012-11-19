--Defines data structures and functions for manipulating predicates
import           Data.IP

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

--Combining Predicates
translateRule (Rule (Neg p) a) =
    translateRule (Rule p (flipAction a))

translateRule (Rule (OR p q) a) =
    translateRule p a ++ "\n" ++ translateRule q a

--De Morgan's law
translateRule (Rule (AND p q) a) =
    translateRule $ NOT $ OR (NOT p) (NOT q)

--We need to support the idea of chains for these.
--translateRule (Rule (AND p q) a) =
--translateRule (Rule (OR p q) a) =
