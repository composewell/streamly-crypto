-- |
-- Module      : Streamly.Crypto.Orphans
-- Copyright   : (c) 2021 Composewell Technologies
--
-- License     : Apache-2.0
-- Maintainer  : streamly@composewell.com
-- Stability   : experimental
-- Portability : GHC

{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE FlexibleInstances #-}

module Streamly.Crypto.Orphans where

import Data.ByteArray ( ByteArrayAccess(..), ByteArray(..) )
import Data.Word (Word8)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.ForeignPtr.Unsafe (unsafeForeignPtrToPtr)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Streamly.Memory.Array (Array)
import qualified Streamly.Internal.Memory.Array.Types as Array

instance ByteArrayAccess (Array Word8) where
    length = Array.byteLength
    withByteArray array func =
        withForeignPtr
            (Array.aStart array)
            (func . castPtr)
    copyByteArrayToPtr array ptr =
        withForeignPtr
            (Array.aStart array)
            (\arrayPtr -> Array.memcpy
                (castPtr ptr)
                (castPtr arrayPtr)
                (Array.byteLength array))

{-# INLINE withNewArray #-}
withNewArray ::
       Int
    -> (Ptr p -> IO b)
    -> IO (b, Array Word8)
withNewArray size f = do
    arr <- Array.newArray size
    b <- withForeignPtr (Array.aStart arr) (f . castPtr)
    return (b, arr { Array.aEnd = unsafeForeignPtrToPtr (Array.aStart arr) `plusPtr` size
                   , Array.aBound = unsafeForeignPtrToPtr (Array.aStart arr) `plusPtr` size})

instance ByteArray (Array Word8) where
    allocRet = withNewArray
