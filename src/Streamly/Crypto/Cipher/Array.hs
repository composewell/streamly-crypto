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

ecbEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbEncrypt cipher =
    Streamly.map (ecbEncryptArray cipher)
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

ecbDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
ecbDecrypt cipher =
    Streamly.map (ecbDecryptArray cipher)
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcEncrypt cipher iv =
    Streamly.map (cbcEncryptArray cipher iv)
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cbcDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cbcDecrypt cipher iv =
    Streamly.map (cbcDecryptArray cipher iv)
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbEncrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbEncrypt cipher iv =
    Streamly.map (cfbEncryptArray cipher iv)
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD

cfbDecrypt ::
   (BlockCipher cipher, MonadIO m)
   => cipher
   -> IV cipher
   -> SerialT m (Array Word8)
   -> SerialT m (Array Word8)
cfbDecrypt cipher iv =
    Streamly.map (cfbDecryptArray cipher iv)
    . Streamly.arraysOf 256
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
    . Streamly.arraysOf 256
    . StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
