{-# LANGUAGE TypeSynonymInstances #-}
---Here goes nothing!!
--import qualified Data.BitString as BS
import           System.IO

--Change this to output to a different file
outFile = "test.conf"

--Data types describing rules/fields
data Field = Srcip | Dstip

data OptionalBit = Zero | One | Wild
                   deriving Show

--type Pattern = [OptionalBit]  --Bit pattern, with wildcards
--once you run out of bits, the rest are wild
newtype Pattern = Patt [Bool]
instance Show Pattern where
  show (Patt bs) = foldl (\s b -> showOne b : s) [] bs
    where
      showOne True = '0'
      showOne False = '1'

data Pred =
        Header Field Pattern
        | Neg Pred
        | AND Pred Pred
        | OR Pred Pred

--Conv

--Functions on these data types
translateOne :: Pred -> String
translateOne (Header f p) = "iptables -A INPUT -c " ++ iptype ++ " " ++ show p
    where iptype = (case f of
             Srcip -> "srcip"
             Dstip -> "dstip")

-- complete rest of patter for translateOne
translate :: [Pred] -> String
translate ps = concat . map translateOne $ ps

--Should go in a different file ultimately

--Configuration for this file
conf :: [Pred]
--conf =p
--a    [
--     [True, True, False, True]
--    ]

conf = []

--2 ways to do wildcArds. Either allow arbitrary specification, wildcard bits anywhere in pattern (BAD - doesn't match up with what iptables can do; also less useful)
--Or just allow wild suffixes (possible in IPtables using CIDR notation)

--String constants
iptPrefix :: String
iptPrefix = "iptables"

iptInput :: String
iptInput = "-A INPUT"

iptOutput :: String
iptOutput = "-A OUTPUT"

iptAccept :: String
iptAccept = "ACCEPT"

{--
--Convert configuration into text
genIptablesRules :: [Pred] -> String
genIptablesRules = concat . map interpretRule
    where
      interpretRule Header f p =


main = do
  outHandle <- openFile outFile WriteMode
  hPrint outHandle config
      where config = getIptablesRules conf
--}

main = do
     print "hello, world!"
