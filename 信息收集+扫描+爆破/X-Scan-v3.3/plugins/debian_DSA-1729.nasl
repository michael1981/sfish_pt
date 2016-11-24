# This script was automatically generated from the dsa-1729
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35754);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1729");
 script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1729 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in gst-plugins-bad0.10, a
collection of various GStreamer plugins. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2009-0386
	Tobias Klein discovered a buffer overflow in the quicktime stream
	demuxer (qtdemux), which could potentially lead to the execution of
	arbitrary code via crafted .mov files.
CVE-2009-0387
	Tobias Klein discovered an array index error in the quicktime stream
	demuxer (qtdemux), which could potentially lead to the execution of
	arbitrary code via crafted .mov files.
CVE-2009-0397
	Tobias Klein discovered a buffer overflow in the quicktime stream
	demuxer (qtdemux) similar to the issue reported in CVE-2009-0386, which
	could also lead to the execution of arbitrary code via crafted .mov
	files.
For the oldstable distribution (etch), these problems have been fixed in
version 0.10.3-3.1+etch1.
For the stable distribution (lenny), these problems have been fixed in
version 0.10.8-4.1~lenny1 of gst-plugins-good0.10, since the affected
plugin has been moved there. The fix was already included in the lenny
release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1729');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2009/dsa-1729
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1729] DSA-1729-1 gst-plugins-bad0.10");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1729-1 gst-plugins-bad0.10");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gstreamer0.10-plugins-bad', release: '4.0', reference: '0.10.3-3.1+etch1');
deb_check(prefix: 'gst-plugins-bad0.10', release: '4.0', reference: '0.10.3-3.1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
