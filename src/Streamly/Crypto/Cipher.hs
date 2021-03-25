-- |
-- Module      : Streamly.Crypto.Cipher
-- Copyright   : (c) 2021 Composewell Technologies
--
-- License     : Apache-2.0
-- Maintainer  : streamly@composewell.com
-- Stability   : experimental
-- Portability : GHC

module Streamly.Crypto.Cipher
    ( ecbEncrypt
    , ecbDecrypt
    , cbcEncrypt
    , cbcDecrypt
    , cfbEncrypt
    , cfbDecrypt
    , ctrCombine
    )
where

import Control.Monad.IO.Class (MonadIO)
import Crypto.Cipher.Types (BlockCipher, IV)
import Crypto.Data.Padding (Format)
import qualified Crypto.Cipher.Types as BlockCipher
import Data.Word (Word8)
import Streamly (SerialT)
import qualified Streamly.Internal.Prelude as Streamly
import qualified Streamly.Internal.Data.Stream.StreamD as StreamD
import qualified Streamly.Internal.Memory.Array.Types as Array

import Streamly.Crypto.Orphans ()
import qualified Streamly.Crypto.Cipher.Array as CA

ecbEncrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> SerialT m Word8
    -> SerialT m Word8
ecbEncrypt format cipher =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.ecbEncrypt format cipher
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

ecbDecrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> SerialT m Word8
    -> SerialT m Word8
ecbDecrypt format cipher =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.ecbDecrypt format cipher
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

cbcEncrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> IV cipher
    -> SerialT m Word8
    -> SerialT m Word8
cbcEncrypt format cipher iv =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.cbcEncrypt format cipher iv
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

cbcDecrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> IV cipher
    -> SerialT m Word8
    -> SerialT m Word8
cbcDecrypt format cipher iv =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.cbcDecrypt format cipher iv
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

cfbEncrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> IV cipher
    -> SerialT m Word8
    -> SerialT m Word8
cfbEncrypt format cipher iv =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.cfbEncrypt format cipher iv
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

cfbDecrypt ::
    (BlockCipher cipher, MonadIO m)
    => Format
    -> cipher
    -> IV cipher
    -> SerialT m Word8
    -> SerialT m Word8
cfbDecrypt format cipher iv =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.cfbDecrypt format cipher iv
    . Streamly.arraysOf (BlockCipher.blockSize cipher)

ctrCombine ::
    (BlockCipher cipher, MonadIO m)
    => cipher
    -> IV cipher
    -> SerialT m Word8
    -> SerialT m Word8
ctrCombine cipher iv =
    StreamD.fromStreamD
    . Array.flattenArrays
    . StreamD.toStreamD
    . CA.ctrCombine cipher iv
    . Streamly.arraysOf (BlockCipher.blockSize cipher)
