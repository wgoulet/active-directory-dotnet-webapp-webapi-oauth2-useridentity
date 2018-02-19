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
    /// A KeyBundle consisting of a WebKey plus its attributes.
    /// </summary>
    [DataContract]
    public partial class KeyBundle :  IEquatable<KeyBundle>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyBundle" /> class.
        /// </summary>
        /// <param name="Key">The Json web key..</param>
        /// <param name="Attributes">The key management attributes..</param>
        /// <param name="Tags">Application specific metadata in the form of key-value pairs..</param>
        public KeyBundle(JsonWebKey Key = default(JsonWebKey), KeyAttributes Attributes = default(KeyAttributes), Dictionary<string, string> Tags = default(Dictionary<string, string>))
        {
            this.Key = Key;
            this.Attributes = Attributes;
            this.Tags = Tags;
        }
        
        /// <summary>
        /// The Json web key.
        /// </summary>
        /// <value>The Json web key.</value>
        [DataMember(Name="key", EmitDefaultValue=false)]
        public JsonWebKey Key { get; set; }

        /// <summary>
        /// The key management attributes.
        /// </summary>
        /// <value>The key management attributes.</value>
        [DataMember(Name="attributes", EmitDefaultValue=false)]
        public KeyAttributes Attributes { get; set; }

        /// <summary>
        /// Application specific metadata in the form of key-value pairs.
        /// </summary>
        /// <value>Application specific metadata in the form of key-value pairs.</value>
        [DataMember(Name="tags", EmitDefaultValue=false)]
        public Dictionary<string, string> Tags { get; set; }

        /// <summary>
        /// True if the key&#39;s lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
        /// </summary>
        /// <value>True if the key&#39;s lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.</value>
        [DataMember(Name="managed", EmitDefaultValue=false)]
        public bool? Managed { get; private set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class KeyBundle {\n");
            sb.Append("  Key: ").Append(Key).Append("\n");
            sb.Append("  Attributes: ").Append(Attributes).Append("\n");
            sb.Append("  Tags: ").Append(Tags).Append("\n");
            sb.Append("  Managed: ").Append(Managed).Append("\n");
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
            return this.Equals(obj as KeyBundle);
        }

        /// <summary>
        /// Returns true if KeyBundle instances are equal
        /// </summary>
        /// <param name="other">Instance of KeyBundle to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(KeyBundle other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Key == other.Key ||
                    this.Key != null &&
                    this.Key.Equals(other.Key)
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
                ) && 
                (
                    this.Managed == other.Managed ||
                    this.Managed != null &&
                    this.Managed.Equals(other.Managed)
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
                if (this.Key != null)
                    hash = hash * 59 + this.Key.GetHashCode();
                if (this.Attributes != null)
                    hash = hash * 59 + this.Attributes.GetHashCode();
                if (this.Tags != null)
                    hash = hash * 59 + this.Tags.GetHashCode();
                if (this.Managed != null)
                    hash = hash * 59 + this.Managed.GetHashCode();
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
