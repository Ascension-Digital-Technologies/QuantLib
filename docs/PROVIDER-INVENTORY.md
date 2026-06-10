# Provider Inventory

Provider inventory is available through:

```bash
quantlib-inspect --inventory
```

Each provider reports:

- name
- provider/library version
- availability
- production/experimental classification
- algorithms exposed through the provider boundary

The inventory is intentionally explicit so deployments can reject unexpected provider changes.
