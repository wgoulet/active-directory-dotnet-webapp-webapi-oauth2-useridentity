/* 
 * KeyVaultClient
 *
 * The key vault client performs cryptographic key operations and vault operations against the Key Vault service.
 *
 * OpenAPI spec version: 2016-10-01
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.ComponentModel.DataAnnotations;
using SwaggerDateConverter = IO.Swagger.Client.SwaggerDateConverter;

namespace IO.Swagger.Model
{
    /// <summary>
    /// The issuer for Key Vault certificate.
    /// </summary>
    [DataContract]
    public partial class IssuerBundle :  IEquatable<IssuerBundle>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IssuerBundle" /> class.
        /// </summary>
        /// <param name="Provider">The issuer provider..</param>
        /// <param name="Credentials">The credentials to be used for the issuer..</param>
        /// <param name="OrgDetails">Details of the organization as provided to the issuer..</param>
        /// <param name="Attributes">Attributes of the issuer object..</param>
        public IssuerBundle(string Provider = default(string), IssuerCredentials Credentials = default(IssuerCredentials), OrganizationDetails OrgDetails = default(OrganizationDetails), IssuerAttributes Attributes = default(IssuerAttributes))
        {
            this.Provider = Provider;
            this.Credentials = Credentials;
            this.OrgDetails = OrgDetails;
            this.Attributes = Attributes;
        }
        
        /// <summary>
        /// Identifier for the issuer object.
        /// </summary>
        /// <value>Identifier for the issuer object.</value>
        [DataMember(Name="id", EmitDefaultValue=false)]
        public string Id { get; private set; }

        /// <summary>
        /// The issuer provider.
        /// </summary>
        /// <value>The issuer provider.</value>
        [DataMember(Name="provider", EmitDefaultValue=false)]
        public string Provider { get; set; }

        /// <summary>
        /// The credentials to be used for the issuer.
        /// </summary>
        /// <value>The credentials to be used for the issuer.</value>
        [DataMember(Name="credentials", EmitDefaultValue=false)]
        public IssuerCredentials Credentials { get; set; }

        /// <summary>
        /// Details of the organization as provided to the issuer.
        /// </summary>
        /// <value>Details of the organization as provided to the issuer.</value>
        [DataMember(Name="org_details", EmitDefaultValue=false)]
        public OrganizationDetails OrgDetails { get; set; }

        /// <summary>
        /// Attributes of the issuer object.
        /// </summary>
        /// <value>Attributes of the issuer object.</value>
        [DataMember(Name="attributes", EmitDefaultValue=false)]
        public IssuerAttributes Attributes { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class IssuerBundle {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Provider: ").Append(Provider).Append("\n");
            sb.Append("  Credentials: ").Append(Credentials).Append("\n");
            sb.Append("  OrgDetails: ").Append(OrgDetails).Append("\n");
            sb.Append("  Attributes: ").Append(Attributes).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }
  
        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            return this.Equals(obj as IssuerBundle);
        }

        /// <summary>
        /// Returns true if IssuerBundle instances are equal
        /// </summary>
        /// <param name="other">Instance of IssuerBundle to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(IssuerBundle other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Id == other.Id ||
                    this.Id != null &&
                    this.Id.Equals(other.Id)
                ) && 
                (
                    this.Provider == other.Provider ||
                    this.Provider != null &&
                    this.Provider.Equals(other.Provider)
                ) && 
                (
                    this.Credentials == other.Credentials ||
                    this.Credentials != null &&
                    this.Credentials.Equals(other.Credentials)
                ) && 
                (
                    this.OrgDetails == other.OrgDetails ||
                    this.OrgDetails != null &&
                    this.OrgDetails.Equals(other.OrgDetails)
                ) && 
                (
                    this.Attributes == other.Attributes ||
                    this.Attributes != null &&
                    this.Attributes.Equals(other.Attributes)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            // credit: http://stackoverflow.com/a/263416/677735
            unchecked // Overflow is fine, just wrap
            {
                int hash = 41;
                // Suitable nullity checks etc, of course :)
                if (this.Id != null)
                    hash = hash * 59 + this.Id.GetHashCode();
                if (this.Provider != null)
                    hash = hash * 59 + this.Provider.GetHashCode();
                if (this.Credentials != null)
                    hash = hash * 59 + this.Credentials.GetHashCode();
                if (this.OrgDetails != null)
                    hash = hash * 59 + this.OrgDetails.GetHashCode();
                if (this.Attributes != null)
                    hash = hash * 59 + this.Attributes.GetHashCode();
                return hash;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
