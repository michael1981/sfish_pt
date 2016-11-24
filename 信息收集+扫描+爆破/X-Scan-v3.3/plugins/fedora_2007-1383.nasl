
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1383
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27713);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1383: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1383 (xpdf)");
 script_set_attribute(attribute: "description", value: "Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files. Xpdf is a small and efficient program which uses
standard X fonts.

-
Update Information:

Changes since 3.01: Added anti-aliasing for vector graphics; added the vectorAn
tialias xpdfrc option; added the '-aaVector' switch to xpdf and pdftoppm. Imple
mented stroke adjustment (always enabled by default, ignoring the SA parameter,
to match Adobe's behavior), and added the strokeAdjust xpdfrc command.
Support PDF 1.6 and PDF 1.7. Added support for AES decryption.
Added support for OpenType fonts (only tested with 8-bit CFF data so far). Adde
d user-configurable key/mouse bindings - the bind/unbind xpdfrc commands. Clean
ed up the full-screen mode code and added the ability to toggle it on the fly (
the default key binding is alt-f). Pdfimages with the -j option now writes JPEG
files for 1-component (grayscale) DCT images, in addition to 3-component (RGB)
images. Fixed bugs in handling sampled (type 0) functions with 32-bit samples.
Fixed some things to support DeviceN color spaces with up to 32 colorants. Pdf
tops now constructs the %%Creator and %%Title DSC comments from the
relevant information in the PDF Info dictionary. Tweak the TrueType font encodi
ng deciphering algorithm. Added the 'mapUnkownCharNames' xpdfrc option. Fix a b
ug (that only showed up with certain window managers) in the intermediate resiz
e event optimization. [Thanks to Michael Rogers.] Check for a broken/missing em
bedded font (this was causing xpdf to crash).
Added support for transfer functions in PostScript output.
Be a bit more tolerant of Link destinations that contain null values for positi
oning parameters. Use ordered dot dithering instead of clustered dot dithering
at resolutions below 300 dpi (for monochrome output). Fixed security holes (bou
nds checking issues) in several places. Don't bother creating a SplashFont (all
ocating memory) for fonts that are only used for hidden text - this avoids prob
lems with fonts of unreasonably large sizes.
Clipping in TextOutputDev was off for characters on the left edge of the page.
The scn and SCN operators weren't correctly handling colors with more than four
components. FoFiType1::writeEncoded wasn't always correctly finding the end of
the encoding. Use the ColorTransform parameter in the DCTDecode stream diction
ary. Type 3 fonts are allowed to have a bbox of [0 0 0 0], which means  'unspec
ified' -- don't issue error messages in that case. Perform the transform (to de
vice space) in Splash instead of in SplashOutputDev -- this is needed to correc
tly handle round joins
and caps on stroked paths. PSOutputDev now rasterizes any pages that use trans
parency. Limit the crop, bleed, trim, and art boxes to the edges of the media b
ox (per the PDF spec). Change GString to increase the allocation increment by p
owers of two. Handle whitespace in hex strings in CMap files/streams. Use strin
gs instead of names for separation colorant names in PSOutputDev.
For explicitly masked images where the mask is higher resolution than the image
, use the soft mask code. Avoid problems with very large x-steps in the PostScr
ipt output for tiling pattern fills.
Avoid a divide-by-zero in stitching functions which have a subfunction with emp
ty bounds. Honor the 'Hidden', 'NoView', and 'Print' flags on annotations. Rewr
ote the pixel rendering code in Splash to use a single set of pixel pipeline fu
nctions. Added support for transparency groups and soft masks. Fixed the transp
arency blend functions to match the addendum published
by Adobe. Changed Splash/SplashBitmap to store alpha in a separate plane. Sett
ing the color space now selects the correct default color for that color space.
Remove the mutex lock from GlobalParams::getErrQuiet() to avoid a deadlock whe
n parseCIDToUnicode() or parseUnicodeToUnicode() calls it from inside a locked
section. Added error checking (on the argument count) in the sc/SC/scn/SCN oper
ators. Skip over notdef glyphs in TrueType fonts (which sometimes get drawn as
little boxes), to match Adobe's behavior. Painting operations in a Separation c
olor space with the 'None' colorant or a DeviceN color space with all colorants
set to 'None' never mark the page. Fixed an obscure bug in the JPX decoder - i
t wasn't reading the extra stuffing byte in the case where the last byte of a p
acket header was 0xff. Change the TrueType font parser (FoFiTrueType) to change
the glyph count rather than report an error if the 'loca' table is too small.
Fixed a couple of bugs in the JBIG2 decoder. Added stochastic clustered dot dit
hering. Added the screenType, screenSize, screenDotRadius, screenGamma, screenB
lackThreshold, and screenWhiteThreshold xpdfrc settings. PSOutputDev now correc
tly handles invalid Type 3 charprocs which don't start with a d0 or d1 operator
. FreeType 2.2.x support - get rid of the FT_INTERNAL_OBJECTS_H include, and ad
d some 'const' declarations.
Handle PDFDocEncoding in Info dictionary strings. Tweak the xref repair code -
ignore whitespace at the start of lines when looking for objects. Added the '-e
xec' switch to xpdf. Removed the xpdf.viKeys X resource. Changed the color key
/ explicit masked image code in PSOutputDev to generate better PS code, includi
ng a Level 3 option. Tweaked the DEBUG_MEM code for performance. Move the JBIG2
global stream reading code into reset() instead of the constructor - this way,
pdftotext doesn't end up reading the global stream. Added the '-preload' optio
n to pdftops and the psPreload xpdfrc command. Added the 'zoom to selection' co
mmand (on the popup menu). Fix a bug (in xpdf/pdftoppm/pdftops) with tiling pat
terns whose bbox size is different from their xStep/yStep. Implemented stroke w
ith pattern color spaces. Following a link to a page whose CropBox was differen
t from the MediaBox was resulting in an incorrect scroll position. Parse trunca
ted date strings from the Info dictionary correctly. Change FoFiType1 to handle
Type 1 fonts with two /Encoding keys. Extend the PSOutputDev shaded fill code
to handle DeviceCMYK shaded fills in level2sep and level3sep modes. Detect infi
nite loops in the Page tree. Optimized the ASCII85Encoder code. Tweaked the tex
t extractor to do a better job of lining up rows of text. Leave images compress
ed (or re-compress them with RLE) in PostScript output when setting up images f
or forms and Type 3 fonts (or with -preload). Extend FoFiType1 to handle Type 1
fonts with octal character codes in their encodings. Use a custom string forma
tter to avoid problems with locale-based decimal formatting (commas instead of
periods) in PS output.
Allow comments in PostScript-type functions. Change the TrueType font parser (F
oFiTrueType) to delete glyf table entries that are too short.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the xpdf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xpdf-3.02-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
