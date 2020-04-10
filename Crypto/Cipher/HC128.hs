-- |
-- Module      : Crypto.Cipher.HC128
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : Good
--
-- Simple implementation of the HC128 stream cipher.
-- http://en.wikipedia.org/wiki/HC128
--
-- Initial FFI implementation by Peter White <peter@janrain.com>
--
-- Reorganized and simplified to have an opaque context.
--
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.Cipher.HC128
    ( initialize
    , combine
    , generate
    , set_iv
    , State
    ) where

import           Data.Word
import           Foreign.Ptr
import           Crypto.Internal.ByteArray (ScrubbedBytes, ByteArray, ByteArrayAccess)
import qualified Crypto.Internal.ByteArray as B

import           Crypto.Internal.Compat
import           Crypto.Internal.Imports

-- | The encryption state for HC128
newtype State = State ScrubbedBytes
    deriving (ByteArrayAccess,NFData)

-- | C Call for initializing the encryptor
foreign import ccall unsafe "cryptonite_hc128.h cryptonite_hc128_init"
    c_hc128_init :: Ptr Word8 -- ^ The hc128 key
               -> Word32    -- ^ The key length
               -> Ptr State -- ^ The context
               -> IO ()

foreign import ccall unsafe "cryptonite_hc128.h cryptonite_hc128_setiv"
    c_hc128_setiv :: Ptr State
               -> Ptr Word8 -- ^ The hc128 iv
               -> Word32    -- ^ The key length
               -> IO ()


foreign import ccall unsafe "cryptonite_hc128.h cryptonite_hc128_combine"
    c_hc128_combine :: Ptr State        -- ^ Pointer to the permutation
                  -> Ptr Word8      -- ^ Pointer to the clear text
                  -> Word32         -- ^ Length of the clear text
                  -> Ptr Word8      -- ^ Output buffer
                  -> IO ()

-- | HC128 context initialization.
--
-- seed the context with an initial key. the key size need to be
-- adequate otherwise security takes a hit.
initialize :: ByteArrayAccess key
           => key   -- ^ The key
           -> State -- ^ The HC128 context with the key mixed in
initialize key = unsafeDoIO $ do
    st <- B.alloc 9000 $ \stPtr ->
        B.withByteArray key $ \keyPtr -> c_hc128_init keyPtr (fromIntegral $ B.length key) (castPtr stPtr)
    return $ State st

set_iv :: ByteArrayAccess iv
       => State
       -> iv
       -> State
set_iv (State prevSt) iv = unsafeDoIO $
    B.withByteArray iv $ \ivPtr -> do
      st <- B.copy prevSt $ \stPtr ->
                c_hc128_setiv (castPtr stPtr) ivPtr (fromIntegral len)
      return $! State st
   where len = B.length iv

-- | generate the next len bytes of the rc4 stream without combining
-- it to anything.
generate :: ByteArray ba => State -> Int -> (State, ba)
generate ctx len = combine ctx (B.zero len)

-- | HC128 xor combination of the rc4 stream with an input
combine :: ByteArray ba
        => State               -- ^ rc4 context
        -> ba                  -- ^ input
        -> (State, ba)         -- ^ new rc4 context, and the output
combine (State prevSt) clearText = unsafeDoIO $
    B.allocRet len            $ \outptr ->
    B.withByteArray clearText $ \clearPtr -> do
        st <- B.copy prevSt $ \stPtr ->
                c_hc128_combine (castPtr stPtr) clearPtr (fromIntegral len) outptr
        return $! State st
    --return $! (State st, B.PS outfptr 0 len)
  where len = B.length clearText
