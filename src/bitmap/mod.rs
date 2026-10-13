//! Bitmap API re-exported from `rezzy-recon`.

pub use rezzy_recon::bitmap::{
    Bitmap, Bitmap128, Bitmap64, BitmapDecodeError, IntoIter, Iter, Iter128, Iter64,
    BITMAP_FORMAT_VERSION, BITMAP_MAGIC,
};
