module main

import libsodium
import json
import net.http
import cli { Command, Flag }
import os
import encoding.base64

struct RepoSecret {
	key    string
	key_id string
}

struct NewSecret {
	key_id          string
	encrypted_value string
}

struct RemoteSecret {
	name       string
	created_at string
	updated_at string
}

fn main() {
	mut cmd := Command{
		name: 'cli'
		description: 'Manage GitHub repository secrets with ease'
		version: '1.0.0'
	}
	mut add_cmd := Command{
		name: 'add'
		description: 'Add new secret'
		pre_execute: pre_add
		execute: put_secret
		post_execute: post_add
	}
	mut update_cmd := Command{
		name: 'update'
		description: 'Update existing secret'
		pre_execute: pre_update
		execute: put_secret
		post_execute: post_update
	}

	mut secret_name := Flag{
		flag: .string
		name: 'secret-name'
		abbrev: 'n'
		description: 'Name of the secret'
	}

	mut secret_value := Flag{
		flag: .string
		name: 'value'
		abbrev: 'v'
		description: 'Value of the secret'
	}

	mut org_name := Flag{
		flag: .string
		name: 'org'
		abbrev: 'o'
		description: 'Parent organization name or username'
	}

	mut repo_name := Flag{
		flag: .string
		name: 'repo'
		abbrev: 'r'
		description: 'Repository name'
	}

	mut interactive_flag := Flag{
		flag: .bool
		name: 'interactive'
		abbrev: 'i'
		description: 'Run interactive secret setup wizard. Ignores all of the other flags (Not implemented yet)' // TODO: implement interactive mode
	}

	add_cmd.add_flag(secret_name)
	add_cmd.add_flag(secret_value)
	add_cmd.add_flag(org_name)
	add_cmd.add_flag(repo_name)
	add_cmd.add_flag(interactive_flag)

	update_cmd.add_flag(secret_name)
	update_cmd.add_flag(secret_value)
	update_cmd.add_flag(org_name)
	update_cmd.add_flag(repo_name)
	update_cmd.add_flag(interactive_flag)

	cmd.add_command(add_cmd)
	cmd.add_command(update_cmd)

	cmd.setup()
	cmd.parse(os.args)
}

fn pre_add(cmd Command) ! {
	token := get_token() or {
		println(err)
		panic('Failed to read bearer token!')
	}
	header := build_auth_header(token)
	secret_name := cmd.flags.get_string('secret-name') or {
		println(err)
		panic('Failed to get `value` flag: ${err}')
	}
	org_name := cmd.flags.get_string('org') or {
		println(err)
		panic('Failed to get `org` flag: ${err}')
	}
	repo_name := cmd.flags.get_string('repo') or {
		println(err)
		panic('Failed to get `repo` flag: ${err}')
	}

	if check_secret_existence(secret_name, url_builder(secret_name, repo_name, org_name),
		header)
	{
		println('Cannot add already existing secret named, exitting...')
		panic('Secret already exists')
	}
}

fn post_add(cmd Command) ! {
	println('Secret added!')
}

fn pre_update(cmd Command) ! {
	token := get_token() or {
		println(err)
		panic('Failed to read bearer token!')
	}
	header := build_auth_header(token)
	secret_name := cmd.flags.get_string('secret-name') or {
		println(err)
		panic('Failed to get `value` flag: ${err}')
	}
	org_name := cmd.flags.get_string('org') or {
		println(err)
		panic('Failed to get `org` flag: ${err}')
	}
	repo_name := cmd.flags.get_string('repo') or {
		println(err)
		panic('Failed to get `repo` flag: ${err}')
	}

	if !check_secret_existence(secret_name, url_builder(secret_name, repo_name, org_name),
		header) {
		println('Secret does not exist, exitting...')
		panic('Secret does not exist')
	}
}

fn post_update(cmd Command) ! {
	println('Secret updated!')
}

fn get_public_key(url string, auth http.Header) !RepoSecret {
	config := config_builder(url, http.Method.get, auth, '')
	data := http.fetch(config) or {
		println(err)
		panic('Network error 1!')
	}
	return json.decode(RepoSecret, data.body)
}

fn encrypt_secret(secret string, public_key RepoSecret) NewSecret {
	secret_len := secret.len
	key := public_key.key
	mut buf := []u8{len: libsodium.mac_size + secret_len}
	mut secret_buf := []u8{len: secret_len}
	mut key_buf := []u8{len: key.len}
	for i := 0; i < secret.len; i++ {
		secret_buf[i] = secret[i]
	}
	for i := 0; i < key.len; i++ {
		key_buf[i] = key[i]
	}

	key_id := public_key.key_id.clone()
	libsodium.crypto_box_seal(buf.data, secret_buf.data, u64(secret_len), key_buf.data)
	return NewSecret{key_id, base64.encode(buf)}
}

fn put_secret(cmd Command) ! {
	secret_name := cmd.flags.get_string('secret-name') or {
		println(err)
		panic('Failed to get `value` flag: ${err}')
	}
	org_name := cmd.flags.get_string('org') or {
		println(err)
		panic('Failed to get `org` flag: ${err}')
	}
	repo_name := cmd.flags.get_string('repo') or {
		println(err)
		panic('Failed to get `repo` flag: ${err}')
	}

	value := cmd.flags.get_string('value') or {
		println(err)
		panic('Failed to get `value` flag: ${err}')
	}

	url := url_builder(secret_name, repo_name, org_name)
	token := get_token() or {
		println(err)
		panic('Could not get token, aborting')
	}
	auth := build_auth_header(token)

	pub_key := get_public_key(url_builder('public-key', repo_name, org_name), auth) or {
		println(err)
		panic('Failed to get public key')
	}

	config := config_builder(url, http.Method.put, auth, json.encode(encrypt_secret(value,
		pub_key)))
	res := http.fetch(config) or {
		println(err)
		panic('Failed to set secret')
	}
}

fn config_builder(url string, method http.Method, header http.Header, data string) http.FetchConfig {
	return http.FetchConfig{
		url: url
		method: method
		header: header
		data: data
		params: {}
		cookies: {}
		user_agent: 'v.http'
		verbose: false
		validate: false
		verify: ''
		cert: ''
		cert_key: ''
		in_memory_verification: true
		allow_redirect: true
	}
}

fn check_secret_existence(name string, url string, auth http.Header) bool {
	config := config_builder(url, http.Method.get, auth, '')
	data := http.fetch(config) or {
		println(err)
		panic('Network error 2')
	}
	if data.status_code >= 300 {
		return false
	}
	return true
}

fn get_token() !string {
	result := os.execute('gh auth token')
	if result.exit_code == 0 {
		return result.output.trim_space()
	}
	return error('Token not found')
}

fn build_auth_header(token string) http.Header {
	mut header := http.new_header()
	header.add(http.CommonHeader.authorization, 'Bearer ${token}')
	header.add(http.CommonHeader.accept, 'application/vnd.github+json')
	header.add_custom('X-GitHub-Api-Version', '2022-11-28') or {
		println(err)
		panic('Failed to set API version')
	}
	return header
}

fn url_builder(secret_name string, repo string, org string) string {
	return 'https://api.github.com/repos/${org}/${repo}/actions/secrets/${secret_name}'
}
