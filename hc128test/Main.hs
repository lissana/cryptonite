module Main where

import qualified Crypto.Cipher.HC128 as HC128
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

main = do
  let state = HC128.initialize (BC.pack "0123456789012345")
      something = HC128.set_iv state (BC.pack "0123456789012345")
      (state3, adata) = HC128.combine something (BC.pack "wowawow")
  print adata
  print "hi"
