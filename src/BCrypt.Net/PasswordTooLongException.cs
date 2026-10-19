// ReSharper disable once RedundantUsingDirective
using System;
using System.Runtime.Serialization;

namespace BCryptNet
{
#if PRE_CORE
    /// <summary>
    ///     Thrown when a password exceeds bcrypt's 72-byte limit under <see cref="LongPasswordHandling.Throw"/>.
    /// </summary>
    [Serializable]
    public sealed class PasswordTooLongException : ArgumentException
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        private PasswordTooLongException()
        {
        }

        /// <inheritdoc />
        private PasswordTooLongException(SerializationInfo info, StreamingContext streamingContext) : base(info, streamingContext)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        public PasswordTooLongException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public PasswordTooLongException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#else
    /// <summary>
    ///     Thrown when a password exceeds bcrypt's 72-byte limit under <see cref="LongPasswordHandling.Throw"/>.
    /// </summary>
    public sealed class PasswordTooLongException : ArgumentException
    {
        /// <summary>
        ///     Default Constructor
        /// </summary>
        public PasswordTooLongException()
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        public PasswordTooLongException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Initializes a new instance of <see cref="PasswordTooLongException" />.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="innerException"></param>
        public PasswordTooLongException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
#endif
}
