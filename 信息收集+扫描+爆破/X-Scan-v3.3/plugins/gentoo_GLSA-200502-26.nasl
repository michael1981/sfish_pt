# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(17145);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-26");
 script_cve_id("CVE-2005-0484");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-26
(GProFTPD: gprostats format string vulnerability)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has identified a
    format string vulnerability in the gprostats utility.
  
Impact

    An attacker could exploit the vulnerability by performing a specially
    crafted FTP transfer, the resulting ProFTPD transfer log could
    potentially trigger the execution of arbitrary code when parsed by
    GProFTPD.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/gproftpd-8.1.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0484');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-26] GProFTPD: gprostats format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GProFTPD: gprostats format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/gproftpd", unaffected: make_list("ge 8.1.9"), vulnerable: make_list("lt 8.1.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
