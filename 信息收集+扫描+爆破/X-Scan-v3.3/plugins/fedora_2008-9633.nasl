
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9633
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34760);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-9633: optipng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9633 (optipng)");
 script_set_attribute(attribute: "description", value: "OptiPNG is a PNG optimizer that recompresses image files to a smaller size,
without losing any information. This program also converts external formats
(BMP, GIF, PNM and TIFF) to optimized PNG, and performs PNG integrity checks
and corrections.

-
Update Information:

The main reason for this update is a buffer overflow that is removed in this
version, that could be triggered by processing specially crafted bitmap images
(*.bmp).    Aggregated upstream changelog:  ==============================    +
+
Put back a speed optimization, accidentally removed in version 0.6, allowing
singleton trials (-o1) to be bypassed in certain conditions.  !! Fixed an array
overflow in the BMP reader.  !! Fixed the loss of private chunks under the -sni
p
option.   + Produced a more concise on-screen output in the non-verbose mode.
(Thanks to Vincent Lefevre for the suggestion.)   * Added a programming
interface to the optimization engine, in order to facilitate the development of
PNG-optimizing GUI apps and plugins.   ! Fixed processing when image reduction
yields an output larger than the original.  (Thanks to Michael Krishtopa for th
e
report.)   ! Fixed behavior of -preserve.  (Thanks to Bill Koch for the report.
)
- Removed displaying of partial progress when abandoning IDATs under the -v
option.  The percentages displayed were not very accurate.  ++ Implemented
grayscale(alpha)-to-palette reductions.  ++ Improved conversion of bKGD info
during RGB-to-palette reductions.  (Thanks to Matthew Fearnley for the
contribution.)  !! Fixed conversion of bKGD and tRNS during 16-to-8-bit
reductions.  (Thanks to Matthew Fearnley for the report.)   + Added support for
compressed BMP (incl. PNG-compressed BMP, you bet!)   + Improved the speed of
reading raw PNM files.   + Recognized PNG digital signatures (dSIG) and disable
d
optimization in their presence, to preserve their integrity.   + Allowed the
user to enforce the optimization of dSIG'ed files.   + Recognized APNG animatio
n
files and disabled reductions to preserve their integrity.   + Added the -snip
option, to allow the user to 'snip' one image out of a multi-image file, such a
s
animated GIF, multi-page TIFF, or APNG.  (Thanks to [LaughingMan] for the
suggestion.)   + Improved recovery of PNG files with incomplete IDAT.   ! Fixed
behavior of -out and -dir when the input is already optimized.  (Thanks to
Christian Davideck for the report.)   * Provided more detailed image informatio
n
at the start of processing.   * Provided a more detailed summary at the end of
processing, under the presence of the -v option and/or the occurence of
exceptional events.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the optipng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"optipng-0.6.2-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
