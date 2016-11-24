# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-20.xml
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
 script_id(24256);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-20");
 script_cve_id("CVE-2007-0160");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-20
(Centericq: Remote buffer overflow in LiveJournal handling)


    When interfacing with the LiveJournal service, Centericq does not
    appropriately allocate memory for incoming data, in some cases creating
    a buffer overflow.
  
Impact

    An attacker could entice a user to connect to an unofficial LiveJournal
    server causing Centericq to read specially crafted data from the
    server, which could lead to the execution of arbitrary code with the
    rights of the user running Centericq.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Currently, Centericq is unmaintained. As such, Centericq has been
    masked in Portage until it is again maintained.
    # emerge --ask --verbose --unmerge "net-im/centericq"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0160');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-20] Centericq: Remote buffer overflow in LiveJournal handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Centericq: Remote buffer overflow in LiveJournal handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/centericq", unaffected: make_list(), vulnerable: make_list("le 4.21.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
