"""Inspect pydivert.WinDivert.recv signature and capture first exception."""
import inspect
import sys

try:
    import pydivert
    
    # Get the signature
    sig = inspect.signature(pydivert.WinDivert.recv)
    print("=" * 80)
    print("SIGNATURE:")
    print("=" * 80)
    print(f"pydivert.WinDivert.recv{sig}")
    print()
    
    # Get the source code to see exceptions
    print("=" * 80)
    print("SOURCE CODE:")
    print("=" * 80)
    try:
        source = inspect.getsource(pydivert.WinDivert.recv)
        print(source)
    except Exception as e:
        print(f"Could not get source: {e}")
        print("\nTrying to get docstring instead:")
        print(pydivert.WinDivert.recv.__doc__)
    
    print()
    print("=" * 80)
    print("TESTING recv() TO CAPTURE EXCEPTION:")
    print("=" * 80)
    
    # Try to call recv without proper setup to trigger the first exception
    try:
        with pydivert.WinDivert("false") as w:
            # Try to recv with timeout to see what happens
            packet = w.recv(timeout=100)
    except Exception as e:
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception message: {e}")
        print(f"Exception args: {e.args}")
        
        # Get the full exception details
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
        
except ImportError as e:
    print(f"Error importing pydivert: {e}")
    print("Make sure pydivert is installed: pip install pydivert")
    sys.exit(1)
