use crate::{failure, failure::Failure, format::CodeStr, spinner::spin};
use std::{
    collections::HashMap,
    fs::create_dir_all,
    io,
    io::Read,
    path::{Path, PathBuf},
    process::{ChildStdin, Command, Stdio},
    string::ToString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use uuid::Uuid;

// Construct a random image tag.
pub fn random_tag() -> String {
    Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut Uuid::encode_buffer())
        .to_owned()
}

// Query whether an image exists locally.
pub fn image_exists(image: &str, interrupted: &Arc<AtomicBool>) -> Result<bool, Failure> {
    debug!("Checking existence of image {}\u{2026}", image.code_str());

    match run_quiet(
        "Checking existence of image\u{2026}",
        "The image doesn't exist.",
        &vec!["image", "inspect", image]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    ) {
        Ok(_) => Ok(true),
        Err(Failure::Interrupted) => Err(Failure::Interrupted),
        Err(Failure::System(_, _)) | Err(Failure::User(_, _)) => Ok(false),
    }
}

// Push an image.
pub fn push_image(image: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Pushing image {}\u{2026}", image.code_str());

    run_quiet(
        "Pushing image\u{2026}",
        "Unable to push image.",
        &vec!["image", "push", image]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Pull an image.
pub fn pull_image(image: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Pulling image {}\u{2026}", image.code_str());

    run_quiet(
        "Pulling image\u{2026}",
        "Unable to pull image.",
        &vec!["image", "pull", image]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Delete an image.
pub fn delete_image(image: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Deleting image {}\u{2026}", image.code_str());

    run_quiet(
        "Deleting image\u{2026}",
        "Unable to delete image.",
        &vec!["image", "rm", "--force", image]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Create a container and return its ID.
#[allow(clippy::too_many_arguments)]
pub fn create_container(
    image: &str,
    source_dir: &Path,
    environment: &HashMap<String, String>,
    mount_paths: &[PathBuf],
    mount_readonly: bool,
    ports: &[String],
    docker_args: &HashMap<String, Option<String>>,
    location: &Path,
    user: &str,
    command: &str,
    interrupted: &Arc<AtomicBool>,
) -> Result<String, Failure> {
    debug!("Creating container from image {}\u{2026}", image.code_str(),);

    let mut args = vec!["container", "create"]
        .into_iter()
        .map(std::borrow::ToOwned::to_owned)
        .collect::<Vec<_>>();

    args.extend(container_args(
        source_dir,
        environment,
        location,
        mount_paths,
        mount_readonly,
        ports,
        docker_args,
    ));

    args.extend(
        vec![image, "/bin/su", "-c", command, user]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
    );

    Ok(run_quiet(
        "Creating container\u{2026}",
        "Unable to create container.",
        &args,
        interrupted,
    )?
    .trim()
    .to_owned())
}

// Copy files into a container.
pub fn copy_into_container<R: Read>(
    container: &str,
    mut tar: R,
    interrupted: &Arc<AtomicBool>,
) -> Result<(), Failure> {
    debug!(
        "Copying files into container {}\u{2026}",
        container.code_str()
    );

    run_quiet_stdin(
        "Copying files into container\u{2026}",
        "Unable to copy files into the container.",
        &[
            "container".to_owned(),
            "cp".to_owned(),
            "-".to_owned(),
            format!("{}:/", container),
        ],
        |mut stdin| {
            io::copy(&mut tar, &mut stdin)
                .map_err(failure::system("Unable to copy files into the container."))?;

            Ok(())
        },
        interrupted,
    )
    .map(|_| ())
}

// Copy files from a container.
pub fn copy_from_container(
    container: &str,
    paths: &[PathBuf],
    source_dir: &Path,
    destination_dir: &Path,
    interrupted: &Arc<AtomicBool>,
) -> Result<(), Failure> {
    // Copy each path from the container to the host.
    for path in paths {
        debug!(
            "Copying {} from container {}\u{2026}",
            path.to_string_lossy().code_str(),
            container.code_str()
        );

        // `docker container cp` is not idempotent. For example, suppose there is a directory called
        // `/foo` in the container and `/bar` does not exist on the host. Consider the command
        // `docker cp container:/foo /bar`. The first time that command is run, Docker will create
        // the directory `/bar` on the host and copy the files from `/foo` into it. But if you run
        // it again, Docker will copy `/foo` into the directory `/bar`, resulting in `/bar/foo`,
        // which is undesirable. To work around this, we first create the parent directory of the
        // path, and then copy the path into the directory which will always exist. This ensures
        let source = source_dir.join(path);

        let destination = if let Some(parent) = path.parent() {
            destination_dir.join(parent)
        } else {
            destination_dir.to_path_buf()
        };

        create_dir_all(&destination).map_err(failure::system(format!(
            "Unable to create directory {}.",
            destination.to_string_lossy().code_str()
        )))?;

        // Get the path from the container.
        run_quiet(
            "Copying files from the container\u{2026}",
            "Unable to copy files from the container.",
            &[
                "container".to_owned(),
                "cp".to_owned(),
                format!("{}:{}", container, source.to_string_lossy()),
                destination.to_string_lossy().into_owned(),
            ],
            interrupted,
        )?;
    }

    Ok(())
}

// Start a container.
pub fn start_container(container: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Starting container {}\u{2026}", container.code_str());

    run_loud(
        "Unable to start container.",
        &vec!["container", "start", "--attach", container]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Stop a container.
pub fn stop_container(container: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Stopping container {}\u{2026}", container.code_str());

    run_quiet(
        "Stopping container\u{2026}",
        "Unable to stop container.",
        &vec!["container", "stop", container]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Commit a container to an image.
pub fn commit_container(
    container: &str,
    image: &str,
    interrupted: &Arc<AtomicBool>,
) -> Result<(), Failure> {
    debug!(
        "Committing container {} to image {}\u{2026}",
        container.code_str(),
        image.code_str()
    );

    run_quiet(
        "Committing container\u{2026}",
        "Unable to commit container.",
        &vec!["container", "commit", container, image]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Delete a container.
pub fn delete_container(container: &str, interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    debug!("Deleting container {}\u{2026}", container.code_str());

    run_quiet(
        "Deleting container\u{2026}",
        "Unable to delete container.",
        &vec!["container", "rm", "--force", container]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
        interrupted,
    )
    .map(|_| ())
}

// Run an interactive shell.
#[allow(clippy::too_many_arguments)]
pub fn spawn_shell(
    image: &str,
    source_dir: &Path,
    environment: &HashMap<String, String>,
    location: &Path,
    mount_paths: &[PathBuf],
    mount_readonly: bool,
    ports: &[String],
    docker_args: &HashMap<String, Option<String>>,
    user: &str,
    interrupted: &Arc<AtomicBool>,
) -> Result<(), Failure> {
    debug!(
        "Spawning an interactive shell for image {}\u{2026}",
        image.code_str()
    );

    let mut args = vec!["container", "run", "--rm", "--interactive", "--tty"]
        .into_iter()
        .map(std::borrow::ToOwned::to_owned)
        .collect::<Vec<_>>();

    args.extend(container_args(
        source_dir,
        environment,
        location,
        mount_paths,
        mount_readonly,
        ports,
        docker_args,
    ));

    args.extend(
        vec![image, "/bin/su", user]
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>(),
    );

    run_attach("The shell exited with a failure.", &args, interrupted)
}

// This function returns arguments for `docker create` or `docker run`.
fn container_args(
    source_dir: &Path,
    environment: &HashMap<String, String>,
    location: &Path,
    mount_paths: &[PathBuf],
    mount_readonly: bool,
    ports: &[String],
    docker_args: &HashMap<String, Option<String>>,
) -> Vec<String> {
    // Why `--init`? (1) PID 1 is supposed to reap orphaned zombie processes, otherwise they can
    // accumulate. Bash does this, but we run `/bin/sh` in the container, which may or may not be
    // Bash. So `--init` runs Tini (https://github.com/krallin/tini) as PID 1, which properly reaps
    // orphaned zombies. (2) PID 1 also does not exhibit the default behavior (crashing) for signals
    // like SIGINT and SIGTERM. However, PID 1 can still handle these signals by explicitly trapping
    // them. Tini traps these signals and forwards them to the child process. Then the default
    // signal handling behavior of the child process (in our case, `/bin/sh`) works normally.
    let mut args = vec!["--init".to_owned()];

    // Environment
    args.extend(
        environment
            .iter()
            .flat_map(|(variable, value)| {
                vec!["--env".to_owned(), format!("{}={}", variable, value)]
            })
            .collect::<Vec<_>>(),
    );

    // Location
    args.extend(vec![
        "--workdir".to_owned(),
        location.to_string_lossy().into_owned(),
    ]);

    // Mount paths
    args.extend(
        mount_paths
            .iter()
            .flat_map(|mount_path| {
                // [ref:mount_paths_no_commas]
                vec![
                    "--mount".to_owned(),
                    if mount_readonly {
                        format!(
                            "type=bind,source={},target={},readonly",
                            source_dir.join(mount_path).to_string_lossy(),
                            location.join(mount_path).to_string_lossy()
                        )
                    } else {
                        format!(
                            "type=bind,source={},target={}",
                            source_dir.join(mount_path).to_string_lossy(),
                            location.join(mount_path).to_string_lossy()
                        )
                    },
                ]
            })
            .collect::<Vec<_>>(),
    );

    // Ports
    args.extend(
        ports
            .iter()
            .flat_map(|port| {
                vec!["--publish", port]
                    .into_iter()
                    .map(std::borrow::ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );

    // Docker arguments
    args.extend(
        docker_args 
            .iter()
            .map(|(arg, value)| {
                let arg = if arg.len() == 1 {
                    format!("-{}", arg)
                } else {
                    format!("--{}", arg)
                };

                if let Some(value) = value {
                    format!("{}={}", arg, value)
                } else {
                    arg
                }
            })
            .collect::<Vec<_>>(),
    );

    args
}

// Run a command and return its standard output.
fn run_quiet(
    spinner_message: &str,
    error: &str,
    args: &[String],
    interrupted: &Arc<AtomicBool>,
) -> Result<String, Failure> {
    // Render a spinner animation and clear it when we're done.
    let _guard = spin(spinner_message);

    // This is used to determine whether the user interrupted the program during the execution of
    // the child process.
    let was_interrupted = interrupted.load(Ordering::SeqCst);

    // Run the child process.
    let child = command(args).output().map_err(failure::system(format!(
        "{} Perhaps you don't have Docker installed.",
        error
    )))?;

    // Handle the result.
    if child.status.success() {
        Ok(String::from_utf8_lossy(&child.stdout).to_string())
    } else {
        Err(
            if child.status.code().is_none()
                || (!was_interrupted && interrupted.load(Ordering::SeqCst))
            {
                interrupted.store(true, Ordering::SeqCst);
                Failure::Interrupted
            } else {
                Failure::System(
                    format!("{}\n{}", error, String::from_utf8_lossy(&child.stderr)),
                    None,
                )
            },
        )
    }
}

// Run a command and return its standard output. Accepts a closure which receives a pipe to the
// standard input stream of the child process.
fn run_quiet_stdin<W: FnOnce(&mut ChildStdin) -> Result<(), Failure>>(
    spinner_message: &str,
    error: &str,
    args: &[String],
    writer: W,
    interrupted: &Arc<AtomicBool>,
) -> Result<String, Failure> {
    // Render a spinner animation and clear it when we're done.
    let _guard = spin(spinner_message);

    // This is used to determine whether the user interrupted the program during the execution of
    // the child process.
    let was_interrupted = interrupted.load(Ordering::SeqCst);

    // Run the child process.
    let mut child = command(args)
        .stdin(Stdio::piped()) // [tag:run_quiet_stdin_piped]
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failure::system(format!(
            "{} Perhaps you don't have Docker installed.",
            error
        )))?;

    // Pipe data to the child's standard input stream.
    writer(child.stdin.as_mut().unwrap())?; // [ref:run_quiet_stdin_piped]

    // Wait for the child to terminate.
    let output = child.wait_with_output().map_err(failure::system(format!(
        "{} Perhaps you don't have Docker installed.",
        error
    )))?;

    // Handle the result.
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(
            if output.status.code().is_none()
                || (!was_interrupted && interrupted.load(Ordering::SeqCst))
            {
                interrupted.store(true, Ordering::SeqCst);
                Failure::Interrupted
            } else {
                Failure::System(
                    format!("{}\n{}", error, String::from_utf8_lossy(&output.stderr)),
                    None,
                )
            },
        )
    }
}

// Run a command and inherit standard output and error streams.
fn run_loud(error: &str, args: &[String], interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    // This is used to determine whether the user interrupted the program during the execution of
    // the child process.
    let was_interrupted = interrupted.load(Ordering::SeqCst);

    // Run the child process.
    let mut child = command(args)
        .stdin(Stdio::null())
        .spawn()
        .map_err(failure::system(format!(
            "{} Perhaps you don't have Docker installed.",
            error
        )))?;

    // Wait for the child to terminate.
    let status = child.wait().map_err(failure::system(format!(
        "{} Perhaps you don't have Docker installed.",
        error
    )))?;

    // Handle the result.
    if status.success() {
        Ok(())
    } else {
        Err(
            if status.code().is_none() || (!was_interrupted && interrupted.load(Ordering::SeqCst)) {
                interrupted.store(true, Ordering::SeqCst);
                Failure::Interrupted
            } else {
                Failure::System(error.to_owned(), None)
            },
        )
    }
}

// Run a command and inherit standard input, output, and error streams.
fn run_attach(error: &str, args: &[String], interrupted: &Arc<AtomicBool>) -> Result<(), Failure> {
    // This is used to determine whether the user interrupted the program during the execution of
    // the child process.
    let was_interrupted = interrupted.load(Ordering::SeqCst);

    // Run the child process.
    let child = command(args).status().map_err(failure::system(format!(
        "{} Perhaps you don't have Docker installed.",
        error
    )))?;

    // Handle the result.
    if child.success() {
        Ok(())
    } else {
        Err(
            if child.code().is_none() || (!was_interrupted && interrupted.load(Ordering::SeqCst)) {
                interrupted.store(true, Ordering::SeqCst);
                Failure::Interrupted
            } else {
                Failure::System(error.to_owned(), None)
            },
        )
    }
}

// Construct a Docker `Command` from an array of arguments.
fn command(args: &[String]) -> Command {
    let mut command = Command::new("docker");
    for arg in args {
        command.arg(arg);
    }
    command
}

#[cfg(test)]
mod tests {
    use crate::docker::random_tag;

    #[test]
    fn random_impure() {
        assert_ne!(random_tag(), random_tag());
    }
}
