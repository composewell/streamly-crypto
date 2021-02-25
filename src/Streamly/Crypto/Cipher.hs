-- |
-- Module      : Streamly.Crypto.Cipher
-- Copyright   : (c) 2021 Composewell Technologies
--
-- License     : Apache-2.0
-- Maintainer  : streamly@composewell.com
-- Stability   : experimental
-- Portability : GHC

module Streamly.Crypto.Cipher where

import Crypto.Cipher.Types (BlockCipher)
import Foreign.Storable (Storable)
import Streamly (SerialT)

import Streamly.Crypto.Orphans ()

ecbEncrypt ::
    (Ord a, Storable a, BlockCipher cipher)
    => cipher
    -> SerialT m a
    -> SerialT m a
ecbEncrypt = _

ecbDecrypt ::
    (Ord a, Storable a, BlockCipher cipher)
    => cipher
    -> SerialT m a
    -> SerialT m a
ecbDecrypt = _
