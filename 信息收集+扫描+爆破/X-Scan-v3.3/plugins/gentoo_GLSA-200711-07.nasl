# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-07.xml
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
 script_id(27824);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-07");
 script_cve_id("CVE-2007-4965");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-07
(Python: User-assisted execution of arbitrary code)


    Slythers Bro discovered multiple integer overflows in the imageop
    module, one of them in the tovideo() method, in various locations in
    files imageop.c, rbgimgmodule.c, and also in other files.
  
Impact

    A remote attacker could entice a user to process specially crafted
    images with an application using the Python imageop module, resulting
    in the execution of arbitrary code with the privileges of the user
    running the application, or a Denial of Service. Note that this
    vulnerability may or may not be exploitable, depending on the
    application using the module.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python 2.3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.3.6-r3"
    All Python 2.4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.4.4-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4965');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-07] Python: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("rge 2.3.6-r3", "ge 2.4.4-r6"), vulnerable: make_list("lt 2.4.4-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
