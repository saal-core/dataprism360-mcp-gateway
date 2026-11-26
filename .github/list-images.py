#!/usr/bin/env python3
"""Print every container image this repo references, one per line, sorted.

Sources: Dockerfile* (FROM and COPY --from=<image>), docker-compose*.yml
(`image:`) and .github/workflows/*.yml (`image:`, string `container:`,
`uses: docker://`). Build-stage names, `scratch` and values containing `${{`
or `${` (not resolvable here) are skipped. Used by the "Base images" job in
.github/workflows/security.yml. Run from the repo root.
"""

import glob
import re
import sys

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
COPY_FROM_RE = re.compile(r"^\s*COPY\s+.*--from=(\S+)", re.I)
YAML_IMAGE_RE = re.compile(r"^\s*(?:-\s+)?(?:image|container):\s*['\"]?([^'\"\s#]+)")
USES_DOCKER_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?docker://([^'\"\s#]+)")


def dockerfile_images(path):
    images, stages = [], set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = FROM_RE.match(line)
            if m:
                ref, stage = m.group(1), m.group(2)
                if ref.lower() not in stages and ref.lower() != "scratch":
                    images.append(ref)
                if stage:
                    stages.add(stage.lower())
                continue
            m = COPY_FROM_RE.match(line)
            # --from=<stage> or --from=<index> is a build stage, not an image.
            if m and m.group(1).lower() not in stages and not m.group(1).isdigit():
                images.append(m.group(1))
    return images


def yaml_images(path):
    images = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = YAML_IMAGE_RE.match(line) or USES_DOCKER_RE.match(line)
            if m:
                images.append(m.group(1))
    return images


def main():
    found = set()
    for path in glob.glob("**/Dockerfile*", recursive=True):
        if "/.venv/" in f"/{path}" or "node_modules" in path:
            continue
        found.update(dockerfile_images(path))
    yaml_files = (
        glob.glob("docker-compose*.yml")
        + glob.glob("docker-compose*.yaml")
        + glob.glob(".github/workflows/*.yml")
        + glob.glob(".github/workflows/*.yaml")
    )
    for path in yaml_files:
        found.update(yaml_images(path))
    images = sorted(i for i in found if "${" not in i)
    if not images:
        print("no images found", file=sys.stderr)
        return 1
    print("\n".join(images))
    return 0


if __name__ == "__main__":
    sys.exit(main())
