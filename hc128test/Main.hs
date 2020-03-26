module Main where

import qualified Crypto.Cipher.HC128 as HC128
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Word
import qualified TestData as TD
import qualified Hexdump

key :: B.ByteString
key = B.pack [0x42, 0x5B, 0x29, 0xFD, 0xB7, 0x53, 0xC5, 5, 0x83, 0x77, 0xE8, 0xA, 0x50, 0x17, 0x80, 0x75]
iv :: B.ByteString
iv = B.pack [0xDE, 0xAD, 0x45, 0xC1, 0x2A, 0xC8, 0x93, 0xCE, 0xAA, 0, 0xBF, 0xB6, 0x7B, 0x40, 0x19, 0xA7]

main = do
  let state = HC128.initialize key 
      something = HC128.set_iv state iv 
      (state3, adata) = HC128.combine something (B.pack TD.serverData1)
  putStrLn  $ Hexdump.prettyHex adata
