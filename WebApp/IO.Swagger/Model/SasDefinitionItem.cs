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
    /// The SAS definition item containing storage SAS definition metadata.
    /// </summary>
    [DataContract]
    public partial class SasDefinitionItem :  IEquatable<SasDefinitionItem>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SasDefinitionItem" /> class.
        /// </summary>
        /// <param name="Attributes">The SAS definition management attributes..</param>
        /// <param name="Tags">Application specific metadata in the form of key-value pairs..</param>
        public SasDefinitionItem(SasDefinitionAttributes Attributes = default(SasDefinitionAttributes), Dictionary<string, string> Tags = default(Dictionary<string, string>))
        {
            this.Attributes = Attributes;
            this.Tags = Tags;
        }
        
        /// <summary>
        /// The storage SAS identifier.
        /// </summary>
        /// <value>The storage SAS identifier.</value>
        [DataMember(Name="id", EmitDefaultValue=false)]
        public string Id { get; private set; }

        /// <summary>
        /// The storage account SAS definition secret id.
        /// </summary>
        /// <value>The storage account SAS definition secret id.</value>
        [DataMember(Name="sid", EmitDefaultValue=false)]
        public string Sid { get; private set; }

        /// <summary>
        /// The SAS definition management attributes.
        /// </summary>
        /// <value>The SAS definition management attributes.</value>
        [DataMember(Name="attributes", EmitDefaultValue=false)]
        public SasDefinitionAttributes Attributes { get; set; }

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
            sb.Append("class SasDefinitionItem {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Sid: ").Append(Sid).Append("\n");
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
            return this.Equals(obj as SasDefinitionItem);
        }

        /// <summary>
        /// Returns true if SasDefinitionItem instances are equal
        /// </summary>
        /// <param name="other">Instance of SasDefinitionItem to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SasDefinitionItem other)
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
                    this.Sid == other.Sid ||
                    this.Sid != null &&
                    this.Sid.Equals(other.Sid)
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
                if (this.Id != null)
                    hash = hash * 59 + this.Id.GetHashCode();
                if (this.Sid != null)
                    hash = hash * 59 + this.Sid.GetHashCode();
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
