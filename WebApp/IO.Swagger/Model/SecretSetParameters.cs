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
    /// The secret set parameters.
    /// </summary>
    [DataContract]
    public partial class SecretSetParameters :  IEquatable<SecretSetParameters>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretSetParameters" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected SecretSetParameters() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretSetParameters" /> class.
        /// </summary>
        /// <param name="Value">The value of the secret. (required).</param>
        /// <param name="Tags">Application specific metadata in the form of key-value pairs..</param>
        /// <param name="ContentType">Type of the secret value such as a password..</param>
        /// <param name="Attributes">The secret management attributes..</param>
        public SecretSetParameters(string Value = default(string), Dictionary<string, string> Tags = default(Dictionary<string, string>), string ContentType = default(string), SecretAttributes Attributes = default(SecretAttributes))
        {
            // to ensure "Value" is required (not null)
            if (Value == null)
            {
                throw new InvalidDataException("Value is a required property for SecretSetParameters and cannot be null");
            }
            else
            {
                this.Value = Value;
            }
            this.Tags = Tags;
            this.ContentType = ContentType;
            this.Attributes = Attributes;
        }
        
        /// <summary>
        /// The value of the secret.
        /// </summary>
        /// <value>The value of the secret.</value>
        [DataMember(Name="value", EmitDefaultValue=false)]
        public string Value { get; set; }

        /// <summary>
        /// Application specific metadata in the form of key-value pairs.
        /// </summary>
        /// <value>Application specific metadata in the form of key-value pairs.</value>
        [DataMember(Name="tags", EmitDefaultValue=false)]
        public Dictionary<string, string> Tags { get; set; }

        /// <summary>
        /// Type of the secret value such as a password.
        /// </summary>
        /// <value>Type of the secret value such as a password.</value>
        [DataMember(Name="contentType", EmitDefaultValue=false)]
        public string ContentType { get; set; }

        /// <summary>
        /// The secret management attributes.
        /// </summary>
        /// <value>The secret management attributes.</value>
        [DataMember(Name="attributes", EmitDefaultValue=false)]
        public SecretAttributes Attributes { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class SecretSetParameters {\n");
            sb.Append("  Value: ").Append(Value).Append("\n");
            sb.Append("  Tags: ").Append(Tags).Append("\n");
            sb.Append("  ContentType: ").Append(ContentType).Append("\n");
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
            return this.Equals(obj as SecretSetParameters);
        }

        /// <summary>
        /// Returns true if SecretSetParameters instances are equal
        /// </summary>
        /// <param name="other">Instance of SecretSetParameters to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SecretSetParameters other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Value == other.Value ||
                    this.Value != null &&
                    this.Value.Equals(other.Value)
                ) && 
                (
                    this.Tags == other.Tags ||
                    this.Tags != null &&
                    this.Tags.SequenceEqual(other.Tags)
                ) && 
                (
                    this.ContentType == other.ContentType ||
                    this.ContentType != null &&
                    this.ContentType.Equals(other.ContentType)
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
                if (this.Value != null)
                    hash = hash * 59 + this.Value.GetHashCode();
                if (this.Tags != null)
                    hash = hash * 59 + this.Tags.GetHashCode();
                if (this.ContentType != null)
                    hash = hash * 59 + this.ContentType.GetHashCode();
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
