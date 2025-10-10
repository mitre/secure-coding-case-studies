# MSCCS-11 :: CROSS-SITE SCRIPTING IN LIFERAY PORTAL

### Introduction:

Web applications often need to respond to a requested action using information obtained from a persitant data store (e.g., database, file system). If that information contains a copy of user provided input without proper neutralization, then a dangerous attack known as Cross-Site Scripting (XSS) may be possible. The underlying weakness that leads to XSS is annually one of the CWE™ Top 25 Most Dangerous Software Weaknesses, ranking at #2 in 2023 and #1 in 2024. In 2025, such a weakness was discovered in the notifications widget of Liferay Portal. This case study will examine the weakness, the resulting vulnerability, what it allowed an adversary to accomplish, and how the issue was eventually mitigated.

### Software:

**Name:** Liferay Portal  
**Language:** Java  
**URL:** https://github.com/liferay/liferay-portal

### Weakness:

<a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79: Improper Neutralization of Input During Web Page Generation</a>

The weakness exists when a web application's server component fails to properly neutralize (e.g., canonicalize, encode, escape, quote, validate) user-controlled input, and the input is then returned to the user as part of the web application’s response.

There are three types of XSS attacks that take advantage of this type weakness: reflected, stored, and DOM-based. This case study will focus on stored XSS, which is when server-side code stores externally influenced input in a trusted data store, and then at a later time that potentially dangerous data is read back into the application and included in dynamic content. For example, the server component of a web application may process a post by looking at the input parameters provided in the query string and store those parameters in its database (step 3 in the diagram below) for use later in generating a response to a different user’s reqeust that their browser will receive and process (step 5). If that response contains a copy of the orginal input, and if that input contained malicious code embedded by an adversary (step 2 in diagram below), then the injected code will be executed by the user’s browser. A classic example is when an adversary posts a message to a bulletin board application and a different user makes a request to read that post.

<br/><p align="center"><img src="../images/msccs-11-image-1.jpg" width=75% height=75% alt="XSS=identify->send->store->request->reflect->execute"></p><br/>

The success of a stored XSS attack does not depend on the type of web application or where the malicious data is stored. Instead, the adversary is looking for an application that will store their malicious data and then send it without any neutralization to an unsuspecting user whose browser will then execute that data.

### Vulnerability:

<a href="https://www.cve.org/CVERecord?id=CVE-2025-43807">CVE-2025-43807</a> – Published 22 September 2025

Liferay Portal is an open-source enterprise portal web application for integrating information, people and processes across organizational boundaries. Users interact via a series of JSP pages and a back-end server component written in Java handles the requests. A cross-site scripting related weakness was identified in one of Liferay Portal'server modules.

Within the change-tracking-web module, the _getMessage() method fails to properly neutralize a `name` parameter retrieved from a CTCollection. Looking at the vulnerable code, line 143 calls ctCollection.getName() to retrieve the value that has been stored in the portal database. This `name` is added without any nuetralization to the message object defined on line 142 and returned as part of the message on line 140. 

    vulnerable file: modules/apps/change-tracking/change-tracking-web/src/main/java/com/liferay/change/tracking/web/internal/notifications/PublicationInviteUserNotificationHandler.java

    92   private String _getMessage(
    93        UserNotificationEvent userNotificationEvent,
    94        ServiceContext serviceContext)
    95     throws Exception {
    ...
    102    CTCollection ctCollection = _ctCollectionLocalService.fetchCTCollection(
    103        ctCollectionId);
	...
    140    return _language.format(
    141      serviceContext.getLocale(), "x-has-invited-you-to-work-on-x-as-a-x",
    142      new Object[] {
    143        userName, ctCollection.getName(),
    144        _language.get(
    145            serviceContext.getLocale(), _getRoleLabel(roleValue))
    146      },
    147      false);

For this code weakness to be exploitable, two conditions must be met. First, the parameter `name` that is retrived by the call to getName() must be controllable by an adversary such that they can set the value to whatever they want. Second, the code must improperly neutralize (e.g., canonicalize, encode, escape, quote, validate) the adversary provided input such that the value is stored as is within the database and then sent to a user without modification.

*ADVERSARY CONTROLLED INPUT*

Regarding the first condition, there are multiple ways that an adversary can populate the `name` field in database such that it will later be retrieved by the vulnerable code. One example is by editing a publication via the edit_ct_collection.jsp page. The command is set on line 16 via the actionName variable, and is then used on line 56 to direct the server on how to handle the edit publication request (i.e., which Java code on the server to point to). Finally, the user provided `name` is collected from the publicationName field on the web form on lines 88-89

    supporting file modules/apps/change-tracking/change-tracking-web/src/main/resources/META-INF/resources/publications/edit_ct_collection.jsp
    
    16   String actionName = "/change_tracking/edit_ct_collection";
    ...
    56     <liferay-portlet:actionURL name="<%= actionName %>" var="actionURL">
    57       <liferay-portlet:param name="mvcRenderCommandName" value="/change_tracking/view_publications" />
    58       <liferay-portlet:param name="redirect" value="<%= redirect %>" />
    59     </liferay-portlet:actionURL>
    ...
    63     <react:component
    64       module="{ChangeTrackingCollectionEditView} from change-tracking-web"
    65       props='<%=
    66         HashMapBuilder.<String, Object>put(
    67           "actionUrl", actionURL
    ...
    88         ).put(
    89           "publicationName", name
    ...
    98         ).build()
    99       %>'
    100    />

The above request with the user provided value for `name` is handled on the server by the `/change_tracking/edit_ct_collection` MVC command established on line 42. This command is processed starting on line 49 of EditCTCollectionMVCActionCommand.java. The value of the publication `name` is pulled from the request on line 60 and then passed to the add function on line 73.

    supporting file modules/apps/change-tracking/change-tracking-web/src/main/java/com/liferay/change/tracking/web/internal/portlet/action/EditCTCollectionMVCActionCommand.java
    
    39   @Component(
    40     property = {
    41       "jakarta.portlet.name=" + CTPortletKeys.PUBLICATIONS,
    42       "mvc.command.name=/change_tracking/edit_ct_collection"
    43     },
    44     service = MVCActionCommand.class
    45   )
    46   public class EditCTCollectionMVCActionCommand extends BaseMVCActionCommand {
    47
    48   @Override
    49   protected void doProcessAction(
    50           ActionRequest actionRequest, ActionResponse actionResponse)
    51     throws IOException {
    ...
    59     long ctRemoteId = ParamUtil.getLong(actionRequest, "ctRemoteId");
    60     String name = ParamUtil.getString(actionRequest, "name");
    61     String description = ParamUtil.getString(actionRequest, "description");
    ...
    70       CTCollection ctCollection =
    71         _ctCollectionService.addCTCollection(
    72         null, themeDisplay.getCompanyId(),
    73         themeDisplay.getUserId(), ctRemoteId, name,
    74         description);

The addCTCollection() function is implemented in CTCollectionLocalServiceImpl.java on line 130. The adversary provided value for `name` is added to the ctCollection object via setName() on 154, and then saved in the database via the call to update() on line 159. Note that on line 135 the validate() funciton is called which makes sure that the name is less than the defined max length of 75 characters. Note that validating a publication name using only a length check is appropriate if it is acceptable for publication names to contain letters, numbers, and special characters and thus validation can't be used to limit character type.

    supporting file modules/apps/change-tracking/change-tracking-service/src/main/java/com/liferay/change/tracking/service/impl/CTCollectionLocalServiceImpl.java
    
    130  public CTCollection addCTCollection(
    131          String externalReferenceCode, long companyId, long userId,
    132          long ctRemoteId, String name, String description)
    133    throws PortalException {
    134
    135    _validate(name, description);
    ...
    140    CTCollection ctCollection = ctCollectionPersistence.create(
    141        ctCollectionId);
    ...
    154    ctCollection.setName(name);
    ...
    159    ctCollection = ctCollectionPersistence.update(ctCollection);
    ...
    166    return ctCollection;
    167  }
    ...
    1580 private void _validate(String name, String description)
    1581   throws PortalException {
    ...
    1587   int nameMaxLength = ModelHintsUtil.getMaxLength(
    1588     CTCollection.class.getName(), "name");
    1589
    1590   if (name.length() > nameMaxLength) {
    1591     throw new CTCollectionNameException("Name is too long");
    1592   }

The database field that the `name` parameter is stored in is a 75 character string as defined by the SQL CREATE statement on line 102 of CTCollectionModelImpl.java.

    supporting file: modules/apps/change-tracking/change-tracking-service/src/main/java/com/liferay/change/tracking/model/impl/CTCollectionModelImpl.java
    
    102  public static final String TABLE_SQL_CREATE =
    103      "create table CTCollection (mvccVersion LONG default 0 not null,uuid_ VARCHAR(75) null,
             externalReferenceCode VARCHAR(75) null,ctCollectionId LONG not null primary key,companyId LONG,
             userId LONG,createDate DATE null,modifiedDate DATE null,ctRemoteId LONG,schemaVersionId LONG,
             name VARCHAR(75) null,description VARCHAR(200) null,onDemandUserId LONG,shareable BOOLEAN,
             status INTEGER,statusByUserId LONG,statusDate DATE null)";

At this point the user has been able to submit a 75 character or less string as the publication name and that name is stored in the database as is, thus meeting the first condition for the weakness to be exploitable.

*IMPROPER NEUTRALIZATION*

Regarding the second condition, there should be safeguards in the code to ensure that tainted input will not lead to undesired behavior if sent back to the user. This is known as neutralization. There is no neutralization of the tainted input before or after it is saved in the database.

In this case, the value of the `name` parameter is retrieved from the portal database via the call to getName(). The getName() function is located in CTCollectionModelImpl.java and returns the object value on line 606 without any neutralization.

    supporting file: modules/apps/change-tracking/change-tracking-service/src/main/java/com/liferay/change/tracking/model/impl/CTCollectionModelImpl.java

    599  @JSON
    600  @Override
    601  public String getName() {
    602    if (_name == null) {
    603      return "";
    604    }
    605    else {
    606      return _name;
    607    }
    608  }

This value is then used by the vulnerable code in PublicationInviteUserNotificationHandler.java on line 143 which was listed earlier in this section.

### Exploit:

<a href="https://capec.mitre.org/data/definitions/63.html">CAPEC-63: Cross-Site Scripting</a>

To exploit this vulnerability, an adversary can submit a tainted publication name which is stored in the database.

When there is a notification during an invite user ... if userGroupRoles is empty it sends a notification to invite them

NOTIFICATION_TYPE_ADD_ENTRY

notification is picked up by the handler and a message is sent to the user. The message is generated using the vulnerable code and include the publication name without neutralization.

### Fix:

To resolve this issue the source code was modified to include a form of neutralization. The change on lines 144 of the fixed PublicationInviteUserNotificationHandler.java file adds the use of HtmlUtil.escape() to neutralize (e.g., escape) specific charactures in the `name` parameter that carry specific meanings in the context of HTML markup before returning the value of ctCollection.getName() to the user.

    fixed file: modules/apps/change-tracking/change-tracking-web/src/main/java/com/liferay/change/tracking/web/internal/notifications/PublicationInviteUserNotificationHandler.java
    
    141    return _language.format(
    142      serviceContext.getLocale(), "x-has-invited-you-to-work-on-x-as-a-x",
    143      new Object[] {
    144        userName, HtmlUtil.escape(ctCollection.getName()),
    145        _language.get(
    146            serviceContext.getLocale(), _getRoleLabel(roleValue))
    147      },
    148      false);

The HtmlUtil.escape() function is defined by Liferay Portal within the file HtmlUtil.java. This function implements recommendations from OWASP to guard against cross site scripting. Specifically, it replaces certain special characters with an HTML encoding of that character.

    supporting file: portal-kernel/src/com/liferay/portal/kernel/util/impl/HtmlUtil.java
    
    93      if (c == '<') {
    94        replacement = "&lt;";
    95      }
    96      else if (c == '>') {
    97        replacement = "&gt;";
    98      }
    99      else if (c == '&') {
    100       replacement = "&amp;";
    101     }
    102     else if (c == '"') {
    103       replacement = "&#34;";
    104     }
    105     else if (c == '\'') {
    106       replacement = "&#39;";
    107     }
    108     else if (c == '\u00bb') {
    109       replacement = "&#187;";
    110     }
    111     else if (c == '\u2013') {
    112       replacement = "&#8211;";
    113     }
    114     else if (c == '\u2014') {
    115       replacement = "&#8212;";
    116     }
    117     else if (c == '\u2028') {
    118       replacement = "&#8232;";
    119     }
    120     else if (!_isValidXmlCharacter(c) ||
    121              _isUnicodeCompatibilityCharacter(c)) {
    122
    123       replacement = StringPool.SPACE;
    124     }

With proper HTML encoding in place, the `name` parameter can no longer be used to launch a stored cross site scripting attack.

### Conclusion:

Improper neutralization of input is a common weakness that annually ranks among the CWE™ Top 25 Most Dangerous Software Weaknesses, ranking #2 in 2023 and #1 in 2024. The weakness can lead to remote code execution and/or the reading of application data. One such weakness led to a vulnerability that was discovered in the Liferay Portal in 2025. In response, Liferay Portal made changes to implement an effective neutralization of the user-controlled "name" parameter and remove the root cause weakness “Improper Neutralization of Input During Web Page Generation”. Without this weakness, the Liferay Portal code can no longer be exploited via a stored XSS attack to execute JavaScript code in a user's web browser. Software developers should always follow secure coding practices and ensure any user-controlled input is effectively neutralized to avoid such vulnerabilities in their own projects.

### References:

OSV Vulnerability Report: https://osv.dev/vulnerability/GHSA-jh9h-8xf2-25wj

GitHub Advisory Database: https://github.com/advisories/GHSA-jh9h-8xf2-25wj

CVE-2025-43807 Entry: https://www.cve.org/CVERecord?id=CVE-2025-43807

NVD Vulnerability Report: https://nvd.nist.gov/vuln/detail/CVE-2025-43807

CWE-79 Entry: https://cwe.mitre.org/data/definitions/79.html

CAPEC-63 Entry: https://capec.mitre.org/data/definitions/63.html

Liferay Portal Commit to Fix Issue: https://github.com/liferay/liferay-portal/commit/aaf32ff25affc0d63adc79abaedc9f565f033789

### Contributions:

Originally created by Drew Buttner - The MITRE Corporation<br>

(C) 2025 The MITRE Corporation. All rights reserved.<br>
This work is openly licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC-BY-4.0</a>
