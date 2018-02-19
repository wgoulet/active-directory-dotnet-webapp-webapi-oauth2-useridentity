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
    /// The key operations parameters.
    /// </summary>
    [DataContract]
    public partial class KeyOperationsParameters :  IEquatable<KeyOperationsParameters>, IValidatableObject
    {
        /// <summary>
        /// algorithm identifier
        /// </summary>
        /// <value>algorithm identifier</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum AlgEnum
        {
            
            /// <summary>
            /// Enum RSAOAEP for "RSA-OAEP"
            /// </summary>
            [EnumMember(Value = "RSA-OAEP")]
            RSAOAEP,
            
            /// <summary>
            /// Enum RSAOAEP256 for "RSA-OAEP-256"
            /// </summary>
            [EnumMember(Value = "RSA-OAEP-256")]
            RSAOAEP256,
            
            /// <summary>
            /// Enum RSA15 for "RSA1_5"
            /// </summary>
            [EnumMember(Value = "RSA1_5")]
            RSA15
        }

        /// <summary>
        /// algorithm identifier
        /// </summary>
        /// <value>algorithm identifier</value>
        [DataMember(Name="alg", EmitDefaultValue=false)]
        public AlgEnum? Alg { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyOperationsParameters" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected KeyOperationsParameters() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyOperationsParameters" /> class.
        /// </summary>
        /// <param name="Alg">algorithm identifier (required).</param>
        /// <param name="Value">Value (required).</param>
        public KeyOperationsParameters(AlgEnum? Alg = default(AlgEnum?), string Value = default(string))
        {
            // to ensure "Alg" is required (not null)
            if (Alg == null)
            {
                throw new InvalidDataException("Alg is a required property for KeyOperationsParameters and cannot be null");
            }
            else
            {
                this.Alg = Alg;
            }
            // to ensure "Value" is required (not null)
            if (Value == null)
            {
                throw new InvalidDataException("Value is a required property for KeyOperationsParameters and cannot be null");
            }
            else
            {
                this.Value = Value;
            }
        }
        

        /// <summary>
        /// Gets or Sets Value
        /// </summary>
        [DataMember(Name="value", EmitDefaultValue=false)]
        public string Value { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class KeyOperationsParameters {\n");
            sb.Append("  Alg: ").Append(Alg).Append("\n");
            sb.Append("  Value: ").Append(Value).Append("\n");
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
            return this.Equals(obj as KeyOperationsParameters);
        }

        /// <summary>
        /// Returns true if KeyOperationsParameters instances are equal
        /// </summary>
        /// <param name="other">Instance of KeyOperationsParameters to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(KeyOperationsParameters other)
        {
            // credit: http://stackoverflow.com/a/10454552/677735
            if (other == null)
                return false;

            return 
                (
                    this.Alg == other.Alg ||
                    this.Alg != null &&
                    this.Alg.Equals(other.Alg)
                ) && 
                (
                    this.Value == other.Value ||
                    this.Value != null &&
                    this.Value.Equals(other.Value)
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
                if (this.Alg != null)
                    hash = hash * 59 + this.Alg.GetHashCode();
                if (this.Value != null)
                    hash = hash * 59 + this.Value.GetHashCode();
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
            // Alg (string) minLength
            if(this.Alg != null && this.Alg.Length < 1)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for Alg, length must be greater than 1.", new [] { "Alg" });
            }

            yield break;
        }
    }

}
