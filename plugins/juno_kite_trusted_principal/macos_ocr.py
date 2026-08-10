"""Read text out of one image, on this machine, using the OS.

Runs under the system interpreter because the Vision bindings ship with macOS
and are not in the agent's virtualenv. Nothing here reaches the network: the
image never leaves the host, which is the whole point -- a passport scan must
not be posted to a vision API to find out whether it is the right passport.

Usage: /usr/bin/python3 macos_ocr.py <image path>
Prints one recognised line per line of output. Silent when there is no text.
"""
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        import Quartz
        import Vision
        from Foundation import NSURL
    except ImportError:
        return 3

    url = NSURL.fileURLWithPath_(sys.argv[1])
    source = Quartz.CGImageSourceCreateWithURL(url, None)
    if source is None or Quartz.CGImageSourceGetCount(source) < 1:
        return 4
    image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
    if image is None:
        return 4

    request = Vision.VNRecognizeTextRequest.alloc().init()
    request.setRecognitionLevel_(0)  # accurate, not fast
    request.setUsesLanguageCorrection_(True)
    handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(
        image, None
    )
    ok, _error = handler.performRequests_error_([request], None)
    if not ok:
        return 5
    for observation in request.results() or []:
        candidates = observation.topCandidates_(1)
        if candidates:
            sys.stdout.write(candidates[0].string() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
