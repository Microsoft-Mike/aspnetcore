// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace CustomPolicyProvider;

internal class MinimumAgePolicyProvider : IAuthorizationPolicyProvider
{
    const string POLICY_PREFIX = "MinimumAge";
    public DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }
    private readonly IDictionary<int, AuthorizationPolicy> AuthorizationPolicyCache;

    public MinimumAgePolicyProvider(IOptions<AuthorizationOptions> options)
    {
        // ASP.NET Core only uses one authorization policy provider, so if the custom implementation
        // doesn't handle all policies (including default policies, etc.) it should fall back to an
        // alternate provider.
        //
        // In this sample, a default authorization policy provider (constructed with options from the 
        // dependency injection container) is used if this custom provider isn't able to handle a given
        // policy name.
        //
        // If a custom policy provider is able to handle all expected policy names then, of course, this
        // fallback pattern is unnecessary.
        FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);

        // The same MinimumAge might be specified for many endpoints.
        // This PolicyProvider is registered as a Singleton, so it can maintain a cache of built Policies keyed on the MinimumAge.
        // Use the same AuthorizationPolicy instance for all uses of the same MinimumAge
        AuthorizationPolicyCache = new Dictionary<int, AuthorizationPolicy>();
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy> GetFallbackPolicyAsync() => FallbackPolicyProvider.GetFallbackPolicyAsync();

    // Policies are looked up by string name, so expect 'parameters' (like age)
    // to be embedded in the policy names. This is abstracted away from developers
    // by the more strongly-typed attributes derived from AuthorizeAttribute
    // (like [MinimumAgeAuthorize] in this sample)
    public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(POLICY_PREFIX, StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(policyName.Substring(POLICY_PREFIX.Length), out var age))
        {
            lock(this)
            {
                if (AuthorizationPolicyCache.ContainsKey(age)) 
                {
                    return Task.FromResult(AuthorizationPolicy[age]);
                }
                var policy = new AuthorizationPolicyBuilder();
                policy.AddRequirements(new MinimumAgeRequirement(age));
                var builtPolicy = policy.Build();
                AuthorizationPolicy.Add(age, builtPolicy);
                return Task.FromResult(builtPolicy);
            }
        }

        // If the policy name doesn't match the format expected by this policy provider,
        // try the fallback provider. If no fallback provider is used, this would return 
        // Task.FromResult<AuthorizationPolicy>(null) instead.
        return FallbackPolicyProvider.GetPolicyAsync(policyName);
    }
}
