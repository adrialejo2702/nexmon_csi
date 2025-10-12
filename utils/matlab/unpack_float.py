"""
unpack_float.py

Port of the unpack_float.c MEX function to Python
Unpacks CSI data from Nexmon CSI extractor for bcm4358 and bcm4366c0 chips
"""

import numpy as np


K_TOF_UNPACK_SGN_MASK = 1 << 31


def unpack_float_acphy(nbits, autoscale, shft, fmt, nman, nexp, nfft, H):
    """
    Unpack float data for ACPHY chips
    
    Parameters:
    -----------
    nbits : int
        Number of bits
    autoscale : int
        Autoscale flag
    shft : int
        Shift value
    fmt : int
        Format flag
    nman : int
        Mantissa bits
    nexp : int
        Exponent bits
    nfft : int
        FFT size
    H : numpy.ndarray
        Input data (uint32)
        
    Returns:
    --------
    Hout : numpy.ndarray
        Output data (int32) with shape (nfft*2,)
    """
    iq_mask = (1 << (nman - 1)) - 1
    e_mask = (1 << nexp) - 1
    e_p = 1 << (nexp - 1)
    sgnr_mask = 1 << (nexp + 2*nman - 1)
    sgni_mask = sgnr_mask >> nman
    e_zero = -nman
    n_out = nfft << 1
    e_shift = 1
    
    # Initialize arrays
    He = np.zeros(256, dtype=np.int8)
    # Use int64 for intermediate calculations to avoid overflow
    Hout = np.zeros(n_out, dtype=np.int64)
    
    maxbit = -e_p
    
    # First pass: extract values and find maxbit
    for i in range(nfft):
        vi = int((H[i] >> (nexp + nman)) & iq_mask)
        vq = int((H[i] >> nexp) & iq_mask)
        e = int(H[i] & e_mask)
        
        if e >= e_p:
            e -= (e_p << 1)
        
        He[i] = e
        
        x = vi | vq
        if autoscale and x:
            m = 0xffff0000
            b = 0xffff
            s = 16
            while s > 0:
                if x & m:
                    e += s
                    x >>= s
                s >>= 1
                m = (m >> s) & b
                b >>= s
            if e > maxbit:
                maxbit = e
        
        # Apply sign masks
        if H[i] & sgnr_mask:
            vi |= K_TOF_UNPACK_SGN_MASK
        if H[i] & sgni_mask:
            vq |= K_TOF_UNPACK_SGN_MASK
            
        Hout[i << 1] = vi
        Hout[(i << 1) + 1] = vq
    
    # Second pass: scale values
    shft = nbits - maxbit
    for i in range(n_out):
        e = He[i >> e_shift] + shft
        vi = Hout[i]
        sgn = 1
        
        if vi & K_TOF_UNPACK_SGN_MASK:
            sgn = -1
            vi &= ~K_TOF_UNPACK_SGN_MASK
        
        if e < e_zero:
            vi = 0
        elif e < 0:
            e = -e
            vi = vi >> e
        else:
            vi = vi << e
        
        Hout[i] = sgn * vi
    
    # Convert back to int32 for output
    return Hout.astype(np.int32)


def unpack_float(format_type, nfft, H):
    """
    Main unpack_float function matching the MEX interface
    
    Parameters:
    -----------
    format_type : int
        Format type (0 for bcm4358, 1 for bcm4366c0)
    nfft : int
        FFT size
    H : numpy.ndarray
        Input CSI data as uint32 array
        
    Returns:
    --------
    Hout : numpy.ndarray
        Unpacked CSI data as int32 array with shape (nfft*2,)
    """
    if format_type == 0:
        # bcm4358 parameters
        return unpack_float_acphy(10, 0, 0, 1, 9, 5, nfft, H)
    elif format_type == 1:
        # bcm4366c0 parameters
        return unpack_float_acphy(10, 0, 0, 1, 12, 6, nfft, H)
    else:
        raise ValueError("format_type can only be 0 or 1")

