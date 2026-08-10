"""Read text out of one image, on this machine, using the OS.

Runs under the system interpreter because the Vision bindings ship with macOS
and are not in the agent's virtualenv. Nothing here reaches the network: the
image never leaves the host, which is the whole point -- a passport scan must
not be posted to a vision API to find out whether it is the right passport.

Usage: /usr/bin/python3 macos_ocr.py <image path>
Prints one recognised line per line of output. Silent when there is no text.
"""
import sys


_PDF_RENDER_SCALE = 2.0


def _first_page_image(Quartz, url):
    """The first page as a bitmap, whether this is an image or a PDF.

    A scanned document is very often a PDF with no text layer -- pdftotext
    returns nothing for it, and without this it stays unidentifiable, which is
    exactly the case the preview exists to solve.
    """
    source = Quartz.CGImageSourceCreateWithURL(url, None)
    if source is not None and Quartz.CGImageSourceGetCount(source) >= 1:
        image = Quartz.CGImageSourceCreateImageAtIndex(source, 0, None)
        if image is not None:
            return image

    document = Quartz.CGPDFDocumentCreateWithURL(url)
    if document is None or Quartz.CGPDFDocumentGetNumberOfPages(document) < 1:
        return None
    page = Quartz.CGPDFDocumentGetPage(document, 1)
    if page is None:
        return None
    box = Quartz.CGPDFPageGetBoxRect(page, Quartz.kCGPDFMediaBox)
    width = int(box.size.width * _PDF_RENDER_SCALE)
    height = int(box.size.height * _PDF_RENDER_SCALE)
    if width < 1 or height < 1 or width * height > 40_000_000:
        return None
    context = Quartz.CGBitmapContextCreate(
        None, width, height, 8, 0,
        Quartz.CGColorSpaceCreateDeviceRGB(),
        Quartz.kCGImageAlphaNoneSkipLast,
    )
    if context is None:
        return None
    Quartz.CGContextSetRGBFillColor(context, 1.0, 1.0, 1.0, 1.0)
    Quartz.CGContextFillRect(context, Quartz.CGRectMake(0, 0, width, height))
    Quartz.CGContextScaleCTM(context, _PDF_RENDER_SCALE, _PDF_RENDER_SCALE)
    Quartz.CGContextTranslateCTM(context, -box.origin.x, -box.origin.y)
    Quartz.CGContextDrawPDFPage(context, page)
    return Quartz.CGBitmapContextCreateImage(context)


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
    image = _first_page_image(Quartz, url)
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
