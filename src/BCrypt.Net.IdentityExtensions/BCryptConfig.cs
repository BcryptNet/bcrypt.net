// /*
// The MIT License (MIT)
// Copyright (c) 2006 Damien Miller djm@mindrot.org (jBCrypt)
// Copyright (c) 2013 Ryan D. Emerle (.Net port)
// Copyright (c) 2016 Chris McKee (.Net-core port / patches / new features)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
// (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
// */

using BCryptNet.IdentityExtensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for setting up BCrypt password hashing services in an <see cref="IServiceCollection" />.
/// </summary>
public static class BCryptNetPasswordHasher
{
    /// <summary>
    /// Set the IPasswordHasher to use BCrypt for password hashing.
    /// </summary>
    /// <remarks>
    /// Configure with <c>services.Configure&lt;BCryptHasherOptions&gt;(...)</c> or the overload taking an action.
    /// Options are validated at startup and changes apply without a restart.
    /// </remarks>
    /// <param name="services"></param>
    /// <typeparam name="TUser"></typeparam>
    /// <returns></returns>
    public static IServiceCollection UseBcrypt<TUser>(this IServiceCollection services) where TUser : class
    {
        services.AddOptions<BCryptHasherOptions>().ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<BCryptHasherOptions>, BCryptHasherOptionsValidator>());
        services.AddScoped<PasswordHasher<TUser>>();
        // Factory, as the container finds the IOptions and IOptionsMonitor constructors ambiguous
        return services.AddScoped<IPasswordHasher<TUser>>(sp => new BCryptPasswordHasher<TUser>(
            sp.GetRequiredService<PasswordHasher<TUser>>(),
            sp.GetRequiredService<IOptionsMonitor<BCryptHasherOptions>>(),
            sp.GetService<ILogger<BCryptPasswordHasher<TUser>>>()));
    }

    /// <summary>
    /// Set the IPasswordHasher to use BCrypt for password hashing, configured by <paramref name="configure"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// services.UseBcrypt&lt;IdentityUser&gt;(o =>
    /// {
    ///     o.WorkFactor = 12;
    ///     o.PreHash = new PreHashOptions { Scheme = PreHashScheme.HmacSha3, HmacKey = configuration["Pepper"] };
    ///     o.PreviousPreHashes.Add(new PreHashOptions()); // plain bcrypt
    /// });
    /// </code>
    /// </example>
    /// <param name="services"></param>
    /// <param name="configure">Configures the <see cref="BCryptHasherOptions"/>.</param>
    /// <param name="configure">Configures the options.</param>
    /// <typeparam name="TUser"></typeparam>
    /// <returns></returns>
    public static IServiceCollection UseBcrypt<TUser>(this IServiceCollection services, Action<BCryptHasherOptions> configure) where TUser : class
    {
        ArgumentNullException.ThrowIfNull(configure);
        services.Configure(configure);
        return services.UseBcrypt<TUser>();
    }
}
