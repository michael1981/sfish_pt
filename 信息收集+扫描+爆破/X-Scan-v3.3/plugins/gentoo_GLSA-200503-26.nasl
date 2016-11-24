# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-26.xml
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
 script_id(17582);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-26");
 script_cve_id("CVE-2005-0667");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-26
(Sylpheed, Sylpheed-claws: Message reply overflow)


    Sylpheed and Sylpheed-claws fail to properly handle non-ASCII
    characters in email headers when composing reply messages.
  
Impact

    An attacker can send an email containing a malicious non-ASCII
    header which, when replied to, would cause the program to crash,
    potentially allowing the execution of arbitrary code with the
    privileges of the user running the software.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sylpheed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-1.0.3"
    All Sylpheed-claws users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-claws-1.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://sylpheed.good-day.net/#changes');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0667');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-26] Sylpheed, Sylpheed-claws: Message reply overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sylpheed, Sylpheed-claws: Message reply overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/sylpheed-claws", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/sylpheed", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
