# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-07.xml
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
 script_id(26947);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200710-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-07
(Tk: Buffer overflow)


    Reinhard Max discovered a boundary error in Tk when processing an
    interlaced GIF with two frames where the second is smaller than the
    first one.
  
Impact

    A remote attacker could entice a user to open a specially crafted GIF
    image with a Tk-based software, possibly resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4851

');
script_set_attribute(attribute:'solution', value: '
    All Tk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/tk-8.4.15-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-07.xml');
script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-07] Tk: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_cve_id("CVE-2007-5137");
 script_summary(english: 'Tk: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/tk", unaffected: make_list("ge 8.4.15-r1"), vulnerable: make_list("lt 8.4.15-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
