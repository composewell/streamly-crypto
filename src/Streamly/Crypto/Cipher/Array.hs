-- |
-- Module      : Streamly.Crypto.Cipher.Array
-- Copyright   : (c) 2021 Composewell Technologies
--
-- License     : Apache-2.0
-- Maintainer  : streamly@composewell.com
-- Stability   : experimental
-- Portability : GHC

module Streamly.Crypto.Cipher.Array where

import Control.Monad.IO.Class (MonadIO)
import Crypto.Cipher.Types (BlockCipher, IV)
import Crypto.Data.Padding (Format)
import qualified Crypto.Data.Padding as Padding
import qualified Crypto.Cipher.Types as BlockCipher
import Data.Word (Word8)
import Streamly (SerialT)
import qualified Streamly.Prelude as Streamly
import qualified Streamly.Internal.Prelude as Streamly
import qualified Streamly.Internal.Data.Stream.StreamD as StreamD
import Streamly.Memory.Array (Array)
import qualified Streamly.Internal.Memory.Array.Types as Array

import Streamly.Crypto.Orphans ()

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE ecbEncryptArray #-}
ecbEncryptArray ::
    (BlockCipher cipher)
    => cipher
    -> Array Word8
    -> Array Word8
ecbEncryptArray = BlockCipher.ecbEncrypt

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE ecbDecryptArray #-}
ecbDecryptArray ::
    (BlockCipher cipher)
    => cipher
    -> Array Word8
    -> Array Word8
ecbDecryptArray = BlockCipher.ecbDecrypt

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE cbcEncryptArray #-}
cbcEncryptArray ::
    (BlockCipher cipher)
    => cipher
    -> IV cipher
    -> Array Word8
    -> Array Word8
cbcEncryptArray = BlockCipher.cbcEncrypt

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE cbcDecryptArray #-}
cbcDecryptArray ::
    (BlockCipher cipher)
    => cipher
    -> IV cipher
    -> Array Word8
    -> Array Word8
cbcDecryptArray = BlockCipher.cbcDecrypt

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE cfbEncryptArray #-}
cfbEncryptArray ::
    (BlockCipher cipher)
    => cipher
    -> IV cipher
    -> Array Word8
    -> Array Word8
cfbEncryptArray = BlockCipher.cfbEncrypt

-- | length of input array must be multiples of block size of the cipher
-- used.
{-# INLINE cfbDecryptArray #-}
cfbDecryptArray ::
    (BlockCipher cipher)
    => cipher
    -> IV cipher
    -> Array Word8
    -> Array Word8
cfbDecryptArray = BlockCipher.cfbDecrypt

-- | length of input array need not be multiples of block size of the cipher
-- used.
{-# INLINE ctrCombineArray #-}
ctrCombineArray ::
    (BlockCipher cipher)
    => cipher
    -> IV cipher
    -> Array Word8
    -> Array Word8
ctrCombineArray = BlockCipher.ctrCombine

ecbEncrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbEncrypt_ cipher =
    Streamly.map (ecbEncryptArray cipher)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

ecbDecrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbDecrypt_ cipher =
    Streamly.map (ecbDecryptArray cipher)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcEncrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcEncrypt_ cipher iv =
    Streamly.map (cbcEncryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcDecrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcDecrypt_ cipher iv =
    Streamly.map (cbcDecryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbEncrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbEncrypt_ cipher iv =
    Streamly.map (cfbEncryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbDecrypt_ ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbDecrypt_ cipher iv =
    Streamly.map (cfbDecryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

data MapLast s x = Begin s | Continue x s | End

mapLastD :: Monad m => (Array Word8 -> Array Word8) -> StreamD.Stream m (Array Word8) -> StreamD.Stream m (Array Word8)
mapLastD f (StreamD.Stream stepa state) = StreamD.Stream stepb (Begin state)
    where
    stepb gst (Begin st) = do
        r <- stepa gst st
        return $ case r of
            StreamD.Yield x s -> StreamD.Skip $ Continue x s
            StreamD.Skip s -> StreamD.Skip $ Begin s
            StreamD.Stop -> StreamD.Stop
    stepb gst (Continue prev st) = do
        r <- stepa gst st
        return $ case r of
            StreamD.Yield x s -> StreamD.Yield prev (Continue x s)
            StreamD.Skip s -> StreamD.Skip $ Continue prev s
            StreamD.Stop -> StreamD.Yield (f prev) End
    stepb _ End = return StreamD.Stop

mapLast ::
    Monad m
    => (Array Word8 -> Array Word8)
    -> SerialT m (Array Word8)
    -> SerialT m (Array Word8)
mapLast f = StreamD.fromStreamD . mapLastD f . StreamD.toStreamD

maybeDropLastD :: Monad m => (Array Word8 -> Maybe (Array Word8)) -> StreamD.Stream m (Array Word8) -> StreamD.Stream m (Array Word8)
maybeDropLastD f (StreamD.Stream stepa state) = StreamD.Stream stepb (Begin state)
    where
    stepb gst (Begin st) = do
        r <- stepa gst st
        return $ case r of
            StreamD.Yield x s -> StreamD.Skip $ Continue x s
            StreamD.Skip s -> StreamD.Skip $ Begin s
            StreamD.Stop -> StreamD.Stop
    stepb gst (Continue prev st) = do
        r <- stepa gst st
        return $ case r of
            StreamD.Yield x s -> StreamD.Yield prev (Continue x s)
            StreamD.Skip s -> StreamD.Skip $ Continue prev s
            StreamD.Stop -> case f prev of
                Just content -> StreamD.Yield content End
                _            -> StreamD.Stop
    stepb _ End = return StreamD.Stop

maybeDropLast :: Monad m => (Array Word8 -> Maybe (Array Word8)) -> SerialT m (Array Word8) -> SerialT m (Array Word8)
maybeDropLast f = StreamD.fromStreamD . maybeDropLastD f . StreamD.toStreamD

ecbEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format -- ^ Padding format to use.
   -> cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbEncrypt format cipher =
    Streamly.map (ecbEncryptArray cipher)
    . mapLast (Padding.pad format)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

ecbDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format
   -> cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbDecrypt format cipher =
    maybeDropLast (Padding.unpad format)
    . Streamly.map (ecbDecryptArray cipher)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format
   -> cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcEncrypt format cipher iv =
    Streamly.map (cbcEncryptArray cipher iv)
    . mapLast (Padding.pad format)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format
   -> cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcDecrypt format cipher iv =
    maybeDropLast (Padding.unpad format)
    . Streamly.map (cbcDecryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format
   -> cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbEncrypt format cipher iv =
    Streamly.map (cfbEncryptArray cipher iv)
    . mapLast (Padding.pad format)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => Format
   -> cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbDecrypt format cipher iv =
    maybeDropLast (Padding.unpad format)
    . Streamly.map (cfbDecryptArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

ctrCombine ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ctrCombine cipher iv =
    Streamly.map (ctrCombineArray cipher iv)
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
