# ImagePullBackOff

## Symptoms

- Pod stuck in ImagePullBackOff

## Root Cause

Image not found or registry authentication failure.

## Fix

- Verify image tag
- Check imagePullSecrets
- Validate registry access

## Prevention

- Use CI validation
- Verify image existence before deployment