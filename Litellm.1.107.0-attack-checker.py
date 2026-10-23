#!/usr/bin/env -S python3 -I -S
"""Check for known indicators of the LiteLLM 1.107.0 compromise.

Linux / WSL: python3 -I -S check_litellm.py
Windows:     py -I -S check_litellm.py

Read-only: reports findings and recommended actions; does not perform cleanup.
Without -I -S, startup hooks can run before this script can reject the launch.

Sources (2026-10-22):
https://docs.litellm.ai/blog/security-incident-oct-21-2026
https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer
"""

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    sys.stderr.write(
        "중단: python3 -I -S check_litellm.py 로 실행하세요.\n"
        "Windows: py -I -S check_litellm.py\n"
        "주의: 옵션 없이 시작했다면 Python 시작 훅이 이미 실행됐을 수 있습니다.\n"
    )
    raise SystemExit(2)

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path


MAX_READ = 2 * 1024 * 1024
MARKER = ".pc_once_72129118c59f5636c0bb"
LOCK = "remote_code_loader.lock"
BAD_VERSION = re.compile(r"^litellm[-_]1\.107\.0\.dist-info$", re.I)
HOOK_NAME = re.compile(r"^(?:cook|sitecustomize)(?:\.[^.]+)*\.(?:py|pyc)$", re.I)
PAYLOAD_HASHES = {
    "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25",
    "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea",
    "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa",
    "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465",
}
BAD_DIGESTS = {
    "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e",
    "sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5",
}
# Published as partial digests; these identify candidates, not exact matches.
DIGEST_PREFIXES = ("sha256:c00f9d92c427", "sha256:7b00e91cd2fe")


def default_roots():
    if os.name != "nt":
        roots = [Path.home(), Path(sys.base_prefix) / "lib"]
        roots.extend(Path(p) for p in (
            "/home", "/root", "/usr/lib", "/usr/lib64", "/usr/local/lib",
            "/usr/local/lib64", "/opt", "/srv", "/app", "/workspace",
            "/workspaces", "/etc", "/tmp", "/var/tmp", "/dev/shm",
        ) if Path(p).is_dir())
        return roots

    drive = Path(os.environ.get("SystemDrive", "C:") + "\\")
    roots = [Path.home(), Path(sys.base_prefix), drive / "Users"]
    parents = [
        drive,
        Path(os.environ.get("ProgramFiles", str(drive / "Program Files"))),
        Path(os.environ.get("ProgramData", str(drive / "ProgramData"))),
    ]
    for parent in parents:
        for pattern in ("Python*", "Anaconda*", "Miniconda*", "miniforge*"):
            try:
                roots.extend(parent.glob(pattern))
            except OSError:
                pass
    return roots


def unique_roots(paths):
    """Resolve roots and omit directories already covered by a parent."""
    resolved = sorted(
        {Path(p).expanduser().resolve() for p in paths},
        key=lambda p: (len(p.parts), str(p)),
    )
    result = []
    for path in resolved:
        if not any(path == root or root in path.parents for root in result):
            result.append(path)
    return result


def payload_match(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest in PAYLOAD_HASHES:
        return "published_sha256", digest
    if all(token in data for token in (
        b"letters9813/pythonclient-test", b"remote_code_loader.lock", b"/codepy",
    )):
        return "loader_code_indicators", digest
    if (b"litellm.dev/healthcheck" in data and
            (b"PRIVCOLLECT_ACTIVE" in data or MARKER.encode() in data)):
        return "stealer_code_indicators", digest
    if all(token in data for token in (
        b"eNrdfWt327qu4Pf+Ck/XdCTvxu9HnJyd", b"zlib", b"base64",
    )):
        return "published_encoded_stealer_prefix", digest
    return None, digest


def recommended_actions(kinds, has_errors):
    actions = []
    if kinds & {
        "installed_payload", "exfil_marker", "active_loader_indicator",
        "active_container", "container_execution_trace", "process_execution_trace",
    }:
        actions = [
            "해당 환경의 외부 통신과 일반 Python·pip 실행을 중단하세요.",
            "발견 파일·해시·PID·로그를 보존한 뒤, 악성으로 확인된 프로세스와 파일을 격리하세요.",
            "깨끗한 다른 기기에서 접근 가능했던 키·토큰·세션을 폐기하고 재발급하세요.",
            "감염이 확인된 환경은 신뢰할 수 있는 버전으로 재구축하고, 계정 사용 기록을 점검하세요.",
        ]
    elif kinds and kinds <= {"cached_artifact", "cached_payload"}:
        actions = [
            "설치·실행 이력을 먼저 확인하세요. 캐시만으로 감염을 확정할 수 없습니다.",
            "악성 배포물로 확인되면 증거를 보존하고 캐시·미러에서 제거해 재사용을 막으세요.",
        ]
    elif kinds:
        actions = [
            "발견 경로의 파일 내용과 설치·실행 이력을 확인하세요. 파일 이름만으로 삭제하지 마세요.",
            "악성 설치·실행이 확인되면 격리, 환경 재구축, 자격 증명 폐기·재발급을 진행하세요.",
        ]
    if has_errors:
        actions.append("검사 실패한 경로는 권한·존재 여부를 확인하고 다시 검사하세요.")
    return actions


class Scanner:
    def __init__(self):
        self.findings = []
        self._seen = set()
        self.coverage = {
            "roots": [], "files_seen": 0, "startup_files_checked": 0,
            "archives_checked": 0, "symlink_directories_skipped": 0,
            "errors_count": 0, "errors": [], "processes": "not_checked",
            "docker": "not_checked",
        }
        self.limitations = [
            "삭제된 환경, 과거 통신·계정 사용, 알려지지 않은 악성코드는 검사하지 않습니다.",
            "기본 경로 밖의 설치와 건너뛴 링크는 --root로 따로 지정하세요.",
            "분석용 샘플도 탐지될 수 있으므로 발견 경로와 근거를 확인하세요.",
        ]
        if sys.platform.startswith("linux") and "microsoft" in os.uname().release.lower():
            self.limitations.append("WSL 검사입니다. Windows 호스트와 다른 WSL 배포판은 검사하지 않습니다.")

    def add(self, kind, path, detail, **extra):
        path = str(path)
        key = (kind, path)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({"kind": kind, "path": path, "detail": detail, **extra})

    def error(self, path, error):
        self.coverage["errors_count"] += 1
        if len(self.coverage["errors"]) < 20:
            self.coverage["errors"].append({"path": str(path), "error": str(error)})

    def read_small(self, path):
        try:
            # Opening a FIFO could block the scan.
            if not stat.S_ISREG(path.stat().st_mode):
                self.error(path, "일반 파일이 아니므로 읽지 않음")
                return None
            with path.open("rb") as stream:
                data = stream.read(MAX_READ + 1)
            if len(data) > MAX_READ:
                self.error(path, "검사 크기 제한(2 MiB) 초과")
                return None
            return data
        except OSError as exc:
            self.error(path, exc)
            return None

    def inspect_file(self, path):
        name = path.name.lower()
        if name == MARKER:
            self.add("exfil_marker", path, "유출 서버가 HTTP 200을 반환한 뒤 작성되는 표식")
            return
        if name == LOCK:
            self.add("execution_trace", path, "로더 lock 파일: 현재 실행 여부는 미확인")
            return
        if name == "metadata" and BAD_VERSION.match(path.parent.name):
            self.add("version_exposure", path.parent, "1.107.0 설치 메타데이터: 악성 wheel 설치·실행 여부 확인 필요")
            return
        if name.endswith(".whl") and re.match(r"litellm-1\.107\.0-", name):
            self.inspect_archive(path)
            return
        # pip HTTP cache files have hashed names ending in .body.
        if name.endswith(".body") and any(part.lower() == "pip" for part in path.parts):
            self.inspect_archive(path, cache_body=True)
            return
        if not (name.endswith(".pth") or HOOK_NAME.match(name)):
            return
        data = self.read_small(path)
        if data is None:
            return
        self.coverage["startup_files_checked"] += 1
        match, digest = payload_match(data)
        if match:
            in_site_packages = any(
                part.lower() in ("site-packages", "dist-packages") for part in path.parts
            )
            in_stdlib = name == "sitecustomize.py" and re.match(r"python\d+\.\d+$", path.parent.name)
            kind = "installed_payload" if in_site_packages or in_stdlib else "payload_file"
            detail = "공개 악성코드 SHA-256 일치"
            if match != "published_sha256":
                detail = "악성코드 문자열 조합 일치: 코드 확인 필요"
            self.add(kind, path, detail, sha256=digest, match=match)
        elif name.endswith(".pth") and re.search(rb"(?m)^import[ \t]+cook(?:[ \t;.\r\n]|$)", data):
            # 'import cook' alone is not proof of malicious code.
            self.add("suspicious_hook", path, "import cook 시작 훅: cook.py 내용 확인 필요", sha256=digest)

    def inspect_archive(self, path, cache_body=False):
        try:
            if not stat.S_ISREG(path.stat().st_mode):
                return
            if cache_body:
                with path.open("rb") as stream:
                    if stream.read(4) != b"PK\x03\x04":
                        return
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                bad_version = any(
                    BAD_VERSION.match(part)
                    for entry in entries for part in entry.filename.split("/")
                )
                if not bad_version and cache_body:
                    return
                self.coverage["archives_checked"] += 1
                self.add("cached_artifact", path, "1.107.0 wheel 보관 흔적: 설치·실행 여부는 미확인")
                for entry in entries:
                    if entry.filename.rsplit("/", 1)[-1] not in ("cook.py", "sitecustomize.py"):
                        continue
                    if entry.file_size > MAX_READ:
                        self.error(f"{path}!{entry.filename}", "압축 내부 파일 크기 제한 초과")
                        continue
                    with archive.open(entry) as stream:
                        data = stream.read(MAX_READ + 1)
                    match, digest = payload_match(data)
                    if match:
                        self.add(
                            "cached_payload", f"{path}!{entry.filename}",
                            "압축 파일에 악성코드 지표 포함: 설치·실행 여부는 미확인",
                            sha256=digest, match=match,
                        )
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            self.error(path, exc)

    def scan_roots(self, roots):
        roots = unique_roots(roots)
        self.coverage["roots"] = [str(p) for p in roots]
        for root in roots:
            if not root.is_dir():
                self.error(root, "존재하지 않거나 접근할 수 없는 디렉터리")
                continue
            for current, dirs, files in os.walk(
                root, followlinks=False, onerror=lambda exc: self.error(exc.filename, exc),
            ):
                parent = Path(current)
                for name in list(dirs):
                    child = parent / name
                    try:
                        linked = child.is_symlink()
                        if os.name == "nt":
                            attributes = child.lstat().st_file_attributes
                            linked |= bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
                    except OSError as exc:
                        self.error(child, exc)
                        dirs.remove(name)
                        continue
                    if linked:
                        self.coverage["symlink_directories_skipped"] += 1
                        dirs.remove(name)
                    if BAD_VERSION.match(name):
                        self.add("version_exposure", child, "1.107.0 설치 메타데이터: 악성 wheel 설치·실행 여부 확인 필요")
                    if name.startswith((".pc_sq_", ".pc_e_")):
                        self.add("suspicious_temp", child, "정보 수집기가 사용하는 이름의 임시 디렉터리(보조 지표)")
                for name in files:
                    self.coverage["files_seen"] += 1
                    self.inspect_file(parent / name)

    def scan_processes(self, proc_root=Path("/proc")):
        if not sys.platform.startswith("linux"):
            self.coverage["processes"] = "unsupported"
            self.limitations.append("프로세스 환경·lock 소유자 검사는 Linux에서만 지원합니다.")
            return
        self.coverage["processes"] = "linux_proc"
        count = 0
        namespaces = set()
        try:
            pids = list(proc_root.iterdir())
        except OSError as exc:
            self.error(proc_root, exc)
            return
        for pid in pids:
            if not pid.name.isdigit():
                continue
            count += 1
            try:
                # Environment values may contain credentials; report only the PID.
                env = (pid / "environ").read_bytes().split(b"\0")
                if any(v.startswith(b"PRIVCOLLECT_ACTIVE=") for v in env):
                    self.add(
                        "process_execution_trace", f"PID {pid.name}",
                        "PRIVCOLLECT_ACTIVE 발견: 실행 또는 부모 프로세스에서 상속된 흔적",
                    )
            except (FileNotFoundError, ProcessLookupError):
                pass  # A process may exit during inspection.
            except OSError as exc:
                self.error(pid / "environ", exc)
            try:
                for fd in (pid / "fd").iterdir():
                    try:
                        target = os.readlink(fd)
                        clean_target = target[:-10] if target.endswith(" (deleted)") else target
                        if clean_target.rsplit("/", 1)[-1] == LOCK:
                            self.add(
                                "active_loader_indicator", f"PID {pid.name}",
                                "로더 lock 파일을 열고 있음: 현재 실행 의심", target=target,
                            )
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                    except OSError as exc:
                        self.error(fd, exc)
            except (FileNotFoundError, ProcessLookupError):
                pass
            except OSError as exc:
                self.error(pid / "fd", exc)
            try:
                # Containers can have a separate /tmp.
                namespace = os.readlink(pid / "ns/mnt")
                if namespace not in namespaces:
                    temp = pid / "root/tmp"
                    for name in (MARKER, LOCK):
                        path = temp / name
                        try:
                            path.lstat()
                        except FileNotFoundError:
                            continue
                        self.inspect_file(path)
                    namespaces.add(namespace)
            except (FileNotFoundError, ProcessLookupError):
                pass
            except OSError as exc:
                self.error(pid / "root/tmp", exc)
        self.coverage["processes_seen"] = count
        self.coverage["mount_namespaces_checked"] = len(namespaces)

    def scan_docker(self):
        docker = shutil.which("docker")
        if not docker:
            self.coverage["docker"] = "cli_unavailable"
            return
        self.coverage["docker"] = "metadata_only"
        self.limitations.append("Docker 검사는 로컬 daemon의 이미지·컨테이너 메타데이터에 한정됩니다.")

        def run(args, host=None):
            command = [docker]
            env = os.environ.copy()
            if host:
                command.extend(["--host", host])
                env.pop("DOCKER_HOST", None)
                env.pop("DOCKER_CONTEXT", None)
            result = subprocess.run(
                [*command, *args], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20, env=env,
            )
            if result.returncode:
                raise RuntimeError("Docker 조회 실패: daemon 연결·권한을 확인하세요.")
            return result.stdout

        try:
            # Context inspection reads local config, without contacting the daemon.
            if os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"):
                endpoint = os.environ["DOCKER_HOST"]
            else:
                endpoint = run(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"]).strip()
            if not endpoint.startswith(("unix://", "npipe://")):
                self.coverage["docker"] = "remote_endpoint_skipped"
                self.limitations.append("원격 Docker 연결은 건너뛰었습니다.")
                return
            output = run([
                "image", "ls", "-a", "--digests", "--no-trunc", "--format", "{{json .}}"
            ], host=endpoint)
            rows = [json.loads(line) for line in output.splitlines() if line.strip()]
            self.coverage["docker_image_rows"] = len(rows)
            known_ids = set()
            candidate_ids = set()
            for row in rows:
                digest = row.get("Digest", "")
                ref = row.get("Repository", "") + ":" + row.get("Tag", "")
                exact = digest in BAD_DIGESTS or row.get("ID") in BAD_DIGESTS
                candidate = (digest.startswith(DIGEST_PREFIXES) or
                             ("litellm" in ref.lower() and row.get("Tag") in ("1.107.0", "v1.107.0")))
                if exact:
                    known_ids.add(row["ID"])
                    self.add("cached_payload", f"docker:{ref}",
                             "악성 이미지 digest 일치: 실행 여부는 미확인", digest=digest)
                elif candidate:
                    candidate_ids.add(row["ID"])
                    self.add("cached_artifact", f"docker:{ref}",
                             "버전 태그·digest 접두부 일치: 정확한 이미지 확인 필요", digest=digest)
            ids = run(["ps", "-aq", "--no-trunc"], host=endpoint).split()
            self.coverage["docker_containers"] = len(ids)
            if not ids:
                return

            # Avoid Config.Env, which can include credentials.
            template = (
                '{"id":{{json .Id}},"image":{{json .Image}},'
                '"status":{{json .State.Status}},"started":{{json .State.StartedAt}}}'
            )
            output = run(["inspect", "--format", template, *ids], host=endpoint)
            for line in output.splitlines():
                row = json.loads(line)
                if row["image"] not in known_ids | candidate_ids:
                    continue
                kind = "version_exposure"
                detail = "악성 버전 후보 이미지로 만든 컨테이너: 추가 확인 필요"
                if row["image"] in known_ids:
                    detail = "알려진 악성 이미지로 만든 컨테이너"
                    if row["status"] == "running":
                        kind = "active_container"
                    elif row["started"] and not row["started"].startswith("0001-"):
                        kind = "container_execution_trace"
                self.add(kind, "container:" + row["id"], detail,
                         status=row["status"], started=row["started"])
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            self.coverage["docker"] = "incomplete"
            self.error("Docker", exc)

    def report(self):
        kinds = {finding["kind"] for finding in self.findings}
        current = "검사 범위에서 알려진 지표 미발견"
        if kinds & {"active_loader_indicator", "active_container"}:
            current = "악성 로더·컨테이너 실행 지표 발견"
        elif "installed_payload" in kinds:
            current = "Python 설치 경로에서 악성코드 지표 발견"
        elif kinds & {"version_exposure", "suspicious_hook", "payload_file", "suspicious_temp"}:
            current = "확인이 필요한 파일·버전 발견"
        history = "과거 감염 여부 확인 불가: 실행·유출 표식 미발견"
        if "exfil_marker" in kinds:
            history = "유출 성공 응답 표식 발견"
        elif kinds & {"process_execution_trace", "container_execution_trace", "active_loader_indicator", "active_container"}:
            history = "악성코드 실행 관련 지표 발견"
        elif "execution_trace" in kinds:
            history = "로더 lock 파일 발견: 현재 실행 여부 미확인"
        cached_only = bool(kinds) and kinds <= {"cached_artifact", "cached_payload"}
        if cached_only:
            current = "악성·의심 배포물 보관 흔적: 설치·실행 여부는 확인 불가"
        if self.coverage["errors_count"] and not kinds:
            current = "지표 미발견, 일부 항목 검사 불완전"
        exit_code = 0
        if kinds:
            exit_code = 1
        elif self.coverage["errors_count"]:
            exit_code = 2
        return {
            "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "current": current, "history": history,
            "safety": "안전 보장 불가: 미발견 결과로 과거 감염·자격 증명 유출을 배제할 수 없습니다.",
            "findings": self.findings, "coverage": self.coverage, "limitations": self.limitations,
            "recommended_actions": recommended_actions(kinds, self.coverage["errors_count"]),
            "exit_code": exit_code,
        }


def print_report(result):
    print(f"현재 상태: {result['current']}")
    print(f"과거 흔적: {result['history']}")
    print(result["safety"])
    if result["findings"]:
        print(f"\n발견 항목 {len(result['findings'])}개:")
        for finding in result["findings"]:
            print(f"- {finding['path']}\n  {finding['detail']}")
    if result["recommended_actions"]:
        print("\n권장 조치 (자동 실행하지 않음):")
        for index, action in enumerate(result["recommended_actions"], 1):
            print(f"{index}. {action}")

    coverage = result["coverage"]
    print("\n검사 경로: " + ", ".join(coverage["roots"]))
    print(
        f"파일 {coverage['files_seen']:,}개 / 시작 파일 {coverage['startup_files_checked']}개 / "
        f"오류 {coverage['errors_count']}개 / 건너뛴 링크 {coverage['symlink_directories_skipped']}개"
    )
    print(f"프로세스: {coverage['processes']} / Docker: {coverage['docker']}")
    for error in coverage["errors"]:
        print(f"- 검사 실패: {error['path']}: {error['error']}")
    for limitation in result["limitations"]:
        print(f"- {limitation}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="LiteLLM 1.107.0 침해 지표 검사. Python -I -S로 실행하세요.",
        epilog="종료 코드: 0=지표 미발견, 1=발견 항목 있음, 2=검사 불완전/잘못된 실행. 0은 안전 보장이 아닙니다.",
    )
    parser.add_argument("--root", action="append", help="검사 디렉터리(반복 가능). 지정하면 기본 경로를 대체합니다.")
    parser.add_argument("--json", action="store_true", help="JSON 결과를 표준 출력으로 표시")
    parser.add_argument("--skip-processes", action="store_true", help="Linux 프로세스 검사 생략")
    parser.add_argument("--skip-docker", action="store_true", help="Docker 메타데이터 검사 생략")
    args = parser.parse_args(argv)
    scanner = Scanner()
    if not args.json:
        print("LiteLLM 1.107.0 침해 지표 검사 중...", file=sys.stderr, flush=True)
    scanner.scan_roots(args.root or default_roots())
    if not args.skip_processes:
        scanner.scan_processes()
    if not args.skip_docker:
        scanner.scan_docker()
    result = scanner.report()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_report(result)
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
