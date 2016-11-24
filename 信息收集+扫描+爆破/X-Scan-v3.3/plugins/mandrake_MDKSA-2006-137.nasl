
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23886);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:137: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:137 (libtiff).");
 script_set_attribute(attribute: "description", value: "Tavis Ormandy, Google Security Team, discovered several vulnerabilites
the libtiff image processing library:
Several buffer overflows have been discovered, including a stack
buffer overflow via TIFFFetchShortPair() in tif_dirread.c, which is
used to read two unsigned shorts from the input file. While a bounds
check is performed via CheckDirCount(), no action is taken on the
result allowing a pathological tdir_count to read an arbitrary number
of unsigned shorts onto a stack buffer. (CVE-2006-3459)
A heap overflow vulnerability was discovered in the jpeg decoder,
where TIFFScanLineSize() is documented to return the size in bytes
that a subsequent call to TIFFReadScanline() would write, however the
encoded jpeg stream may disagree with these results and overrun the
buffer with more data than expected. (CVE-2006-3460)
Another heap overflow exists in the PixarLog decoder where a run
length encoded data stream may specify a stride that is not an exact
multiple of the number of samples. The result is that on the final
decode operation the destination buffer is overrun, potentially
allowing an attacker to execute arbitrary code. (CVE-2006-3461)
The NeXT RLE decoder was also vulnerable to a heap overflow
vulnerability, where no bounds checking was performed on the result of
certain RLE decoding operations. This was solved by ensuring the
number of pixels written did not exceed the size of the scanline
buffer already prepared. (CVE-2006-3462)
An infinite loop was discovered in EstimateStripByteCounts(), where a
16bit unsigned short was used to iterate over a 32bit unsigned value,
should the unsigned int (td_nstrips) have exceeded USHORT_MAX, the
loop would never terminate and continue forever. (CVE-2006-3463)
Multiple unchecked arithmetic operations were uncovered, including a
number of the range checking operations deisgned to ensure the offsets
specified in tiff directories are legitimate. These can be caused to
wrap for extreme values, bypassing sanity checks. Additionally, a
number of codepaths were uncovered where assertions did not hold true,
resulting in the client application calling abort(). (CVE-2006-3464)
A flaw was also uncovered in libtiffs custom tag support, as
documented here http://www.libtiff.org/v3.6.0.html. While well formed
tiff files must have correctly ordered directories, libtiff attempts
to support broken images that do not. However in certain
circumstances, creating anonymous fields prior to merging field
information from codec information can result in recognised fields
with unexpected values. This state results in abnormal behaviour,
crashes, or potentially arbitrary code execution. (CVE-2006-3465)
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:137");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
script_summary(english: "Check for the version of the libtiff package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libtiff3-3.6.1-12.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-12.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-12.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-12.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3459", value:TRUE);
 set_kb_item(name:"CVE-2006-3460", value:TRUE);
 set_kb_item(name:"CVE-2006-3461", value:TRUE);
 set_kb_item(name:"CVE-2006-3462", value:TRUE);
 set_kb_item(name:"CVE-2006-3463", value:TRUE);
 set_kb_item(name:"CVE-2006-3464", value:TRUE);
 set_kb_item(name:"CVE-2006-3465", value:TRUE);
}
exit(0, "Host is not affected");
