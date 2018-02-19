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
    /// The storage account create parameters.
    /// </summary>
    [DataContract]
    public partial class StorageAccountCreateParameters :  IEquatable<StorageAccountCreateParameters>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="StorageAccountCreateParameters" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected StorageAccountCreateParameters() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="StorageAccountCreateParameters" /> class.
        /// </summary>
        /// <param name="ResourceId">Storage account resource id. (required).</param>
        /// <param name="ActiveKeyName">Current active storage account key name. (required).</param>
        /// <param name="AutoRegenerateKey">whether keyvault should manage the storage account for the user. (required).</param>
        /// <param name="RegenerationPeriod">The key regeneration time duration specified in ISO-8601 format..</param>
        /// <param name="Attributes">The attributes of the storage account..</param>
        /// <param name="Tags">Application specific metadata in the form of key-value pairs..</param>
        public StorageAccountCreateParameters(string ResourceId = default(string), string ActiveKeyName = default(string), bool? AutoRegenerateKey = default(bool?), string RegenerationPeriod = default(string), StorageAccountAttributes Attributes = default(StorageAccountAttributes), Dictionary<string, string> Tags = default(Dictionary<string, string>))
        {
            // to ensure "ResourceId" is required (not null)
            if (ResourceId == null)
            {
                throw new InvalidDataException("ResourceId is a required property for StorageAccountCreateParameters and cannot be null");
            }
            else
            {
                this.ResourceId = ResourceId;
            }
            // to ensure "ActiveKeyName" is required (not null)
            if (ActiveKeyName == null)
            {
                throw new InvalidDataException("ActiveKeyName is a required property for StorageAccountCreateParameters and cannot be null");
            }
            else
            {
                this.ActiveKeyName = ActiveKeyName;
            }
            // to ensure "AutoRegenerateKey" is required (not null)
            if (AutoRegenerateKey == null)
            {
                throw new InvalidDataException("AutoRegenerateKey is a required property for StorageAccountCreateParameters and cannot be null");
            }
            else
            {
                this.AutoRegenerateKey = AutoRegenerateKey;
            }
            this.RegenerationPeriod = RegenerationPeriod;
            this.Attributes = Attributes;
            this.Tags = Tags;
        }
        
        /// <summary>
        /// Storage account resource id.
        /// </summary>
        /// <value>Storage account resource id.</value>
        [DataMember(Name="resourceId", EmitDefaultValue=false)]
        public string ResourceId { get; set; }

        /// <summary>
        /// Current active storage account key name.
        /// </summary>
        /// <value>Current active storage account key name.</value>
        [DataMember(Name="activeKeyName", EmitDefaultValue=false)]
        public string ActiveKeyName { get; set; }

        /// <summary>
        /// whether keyvault should manage the storage account for the user.
        /// </summary>
        /// <value>whether keyvault should manage the storage account for the user.</value>
        [DataMember(Name="autoRegenerateKey", EmitDefaultValue=false)]
        public bool? AutoRegenerateKey { get; set; }

        /// <summary>
        /// The key regeneration time duration specified in ISO-8601 format.
        /// </summary>
        /// <value>The key regeneration time duration specified in ISO-8601 format.</value>
        [DataMember(Name="regenerationPeriod", EmitDefaultValue=false)]
        public string RegenerationPeriod { get; set; }

        /// <summary>
        /// The attributes of the storage account.
        /// </summary>
        /// <value>The attributes of the storage account.</value>
        [DataMember(Name="attributes", EmitDefaultValue=false)]
        public StorageAccountAttributes Attributes { get; set; }

        /// <summary>
        /// Application specific metadata in the form of key-value pairs.
        /// </summary>
        /// <value>Application specific metadata in the form of key-value pairs.</value>
        [DataMember(Name="tags", EmitDefaultValue=false)]
        public Dictionary<string, string> Tags { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class StorageAccountCreateParameters {\n");
            sb.Append("  ResourceId: ").Append(ResourceId).Append("\n");
            sb.Append("  ActiveKeyName: ").Append(ActiveKeyName).Append("\n");
            sb.Append("  AutoRegenerateKey: ").Append(AutoRegenerateKey).Append("\n");
            sb.Append("  RegenerationPeriod: ").Append(RegenerationPeriod).Append("\n");
            sb.Append("  Attributes: ").Append(Attributes).Append("\n");
            sb.Append("  Tags: ").Append(Tags).Append("\n");
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
            return this.Equals(obj as StorageAccountCreateParameters);
        }

        /// <summary>
        /// Returns true if StorageAccountCreateParameters instances are equal
        /// </summary>
        /// <param name="other">Instance of StorageAccountCreateParameters to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(StorageAccountCreateParameters other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.ResourceId == other.ResourceId ||
                    this.ResourceId != null &&
                    this.ResourceId.Equals(other.ResourceId)
                ) && 
                (
                    this.ActiveKeyName == other.ActiveKeyName ||
                    this.ActiveKeyName != null &&
                    this.ActiveKeyName.Equals(other.ActiveKeyName)
                ) && 
                (
                    this.AutoRegenerateKey == other.AutoRegenerateKey ||
                    this.AutoRegenerateKey != null &&
                    this.AutoRegenerateKey.Equals(other.AutoRegenerateKey)
                ) && 
                (
                    this.RegenerationPeriod == other.RegenerationPeriod ||
                    this.RegenerationPeriod != null &&
                    this.RegenerationPeriod.Equals(other.RegenerationPeriod)
                ) && 
                (
                    this.Attributes == other.Attributes ||
                    this.Attributes != null &&
                    this.Attributes.Equals(other.Attributes)
                ) && 
                (
                    this.Tags == other.Tags ||
                    this.Tags != null &&
                    this.Tags.SequenceEqual(other.Tags)
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
                if (this.ResourceId != null)
                    hash = hash * 59 + this.ResourceId.GetHashCode();
                if (this.ActiveKeyName != null)
                    hash = hash * 59 + this.ActiveKeyName.GetHashCode();
                if (this.AutoRegenerateKey != null)
                    hash = hash * 59 + this.AutoRegenerateKey.GetHashCode();
                if (this.RegenerationPeriod != null)
                    hash = hash * 59 + this.RegenerationPeriod.GetHashCode();
                if (this.Attributes != null)
                    hash = hash * 59 + this.Attributes.GetHashCode();
                if (this.Tags != null)
                    hash = hash * 59 + this.Tags.GetHashCode();
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
