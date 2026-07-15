# Dependency licenses

`tailmix.md` is generated with Google's [`go-licenses`][go-licenses] tool using
the same report mechanism as Tailscale's dependency license lists. It covers
the `tailmix` and `tailmixd` binaries for the supported `darwin/arm64` and
`linux/amd64` targets.

Run `make licenses` after changing dependencies. `make licenses-check` rejects
forbidden or newly unknown licenses and verifies that the generated report is
current. CI runs the latter automatically.

## Classifier exception

`github.com/golang/freetype` is intentionally excluded from the automated
unknown-license check. Its root license offers a choice of the FreeType License
or GPL; tailmix uses it under the [FreeType License][freetype-license].
`go-licenses` cannot currently associate that root license with the `raster`
and `truetype` subpackages, so they remain visibly marked `Unknown` in the
generated report. This exception must be reviewed again if the module version
changes.

The source copied into `tsnet/` is handled separately. Its upstream license and
provenance are recorded in [`tsnet/LICENSE`](../tsnet/LICENSE) and
[`tsnet/UPSTREAM`](../tsnet/UPSTREAM).

[go-licenses]: https://github.com/google/go-licenses
[freetype-license]: https://github.com/golang/freetype/blob/e2365dfdc4a0/licenses/ftl.txt
