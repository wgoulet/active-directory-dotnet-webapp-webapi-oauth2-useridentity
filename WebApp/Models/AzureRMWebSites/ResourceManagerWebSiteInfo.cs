using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApp.Models.AzureRMWebSites
{
    public class ResourceManagerWebSites
    {
        public ResourceManagerWebSites()
        {
            webSites = new List<ResourceManagerWebSiteInfo>();
        }
        public List<ResourceManagerWebSiteInfo> webSites { get; set; }
    }
    public class ResourceManagerWebSiteInfo
    {
        public Value[] value { get; set; }
        public object nextLink { get; set; }
        public object id { get; set; }
    }

    public class Value
    {
        public string id { get; set; }
        public string name { get; set; }
        public string type { get; set; }
        public string kind { get; set; }
        public string location { get; set; }
        public Tags tags { get; set; }
        public Properties properties { get; set; }
    }

    public class Tags
    {
        //public string hiddenrelatedsubscriptionsa63628662eda4e4985408b1adffa0401resourcegroupsCondorTestAppprovidersMicrosoftWebserverfarmsServicePlanb0083f4489d5 { get; set; }
    }

    public class Properties
    {
        public string name { get; set; }
        public string state { get; set; }
        public string[] hostNames { get; set; }
        public string webSpace { get; set; }
        public string selfLink { get; set; }
        public string repositorySiteName { get; set; }
        public object owner { get; set; }
        public int usageState { get; set; }
        public bool enabled { get; set; }
        public bool adminEnabled { get; set; }
        public string[] enabledHostNames { get; set; }
        public Siteproperties siteProperties { get; set; }
        public int availabilityState { get; set; }
        public object sslCertificates { get; set; }
        public object[] csrs { get; set; }
        public object cers { get; set; }
        public object siteMode { get; set; }
        public Hostnamesslstate[] hostNameSslStates { get; set; }
        public object computeMode { get; set; }
        public object serverFarm { get; set; }
        public string serverFarmId { get; set; }
        public bool reserved { get; set; }
        public DateTime lastModifiedTimeUtc { get; set; }
        public string storageRecoveryDefaultState { get; set; }
        public int contentAvailabilityState { get; set; }
        public int runtimeAvailabilityState { get; set; }
        public object siteConfig { get; set; }
        public string deploymentId { get; set; }
        public object trafficManagerHostNames { get; set; }
        public string sku { get; set; }
        public bool scmSiteAlsoStopped { get; set; }
        public object targetSwapSlot { get; set; }
        public object hostingEnvironment { get; set; }
        public object hostingEnvironmentProfile { get; set; }
        public bool clientAffinityEnabled { get; set; }
        public bool clientCertEnabled { get; set; }
        public bool hostNamesDisabled { get; set; }
        public object domainVerificationIdentifiers { get; set; }
        public string kind { get; set; }
        public string outboundIpAddresses { get; set; }
        public string possibleOutboundIpAddresses { get; set; }
        public int containerSize { get; set; }
        public int dailyMemoryTimeQuota { get; set; }
        public object suspendedTill { get; set; }
        public int siteDisabledReason { get; set; }
        public object functionExecutionUnitsCache { get; set; }
        public object maxNumberOfWorkers { get; set; }
        public string homeStamp { get; set; }
        public object cloningInfo { get; set; }
        public object snapshotInfo { get; set; }
        public object hostingEnvironmentId { get; set; }
        public Tags1 tags { get; set; }
        public string resourceGroup { get; set; }
        public string defaultHostName { get; set; }
        public object slotSwapStatus { get; set; }
        public bool httpsOnly { get; set; }
    }

    public class Siteproperties
    {
        public object metadata { get; set; }
        public object[] properties { get; set; }
        public object appSettings { get; set; }
    }

    public class Tags1
    {
        public string hiddenrelatedsubscriptionsa63628662eda4e4985408b1adffa0401resourcegroupsCondorTestAppprovidersMicrosoftWebserverfarmsServicePlanb0083f4489d5 { get; set; }
    }

    public class Hostnamesslstate
    {
        public string name { get; set; }
        public int sslState { get; set; }
        public object ipBasedSslResult { get; set; }
        public object virtualIP { get; set; }
        public string thumbprint { get; set; }
        public object toUpdate { get; set; }
        public object toUpdateIpBasedSsl { get; set; }
        public int ipBasedSslState { get; set; }
        public int hostType { get; set; }
    }

}