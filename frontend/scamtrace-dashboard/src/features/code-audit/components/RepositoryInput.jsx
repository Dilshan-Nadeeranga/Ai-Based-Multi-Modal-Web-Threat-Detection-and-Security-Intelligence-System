import { useState } from 'react'

const GITHUB_URL_PATTERN =
  /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}(?:\.git)?\/?$/

export default function RepositoryInput({ onSubmit, loading }) {
  const [url, setUrl] = useState('')
  const [validationError, setValidationError] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    if (loading) return

    const trimmed = url.trim()
    if (!trimmed) {
      setValidationError('Repository URL is required.')
      return
    }
    if (!GITHUB_URL_PATTERN.test(trimmed)) {
      setValidationError(
        'Invalid GitHub URL. Use the form https://github.com/owner/repository.'
      )
      return
    }

    setValidationError('')
    onSubmit(trimmed)
  }

  return (
    <form className="ca-form" onSubmit={handleSubmit} noValidate>
      <label className="ca-form__label" htmlFor="ca-repository-url">
        Repository URL
      </label>
      <input
        id="ca-repository-url"
        className="ca-form__input"
        type="url"
        placeholder="https://github.com/owner/repository"
        value={url}
        onChange={(event) => setUrl(event.target.value)}
        disabled={loading}
        autoComplete="off"
        spellCheck="false"
      />

      {validationError && <p className="ca-error">{validationError}</p>}

      <button className="ca-form__button" type="submit" disabled={loading}>
        {loading ? 'Analyzing repository…' : 'Analyze Repository'}
      </button>

      <p className="ca-form__hint">
        Supported: public JavaScript/TypeScript repositories (Node.js, Express, React, Next.js, Vue, Angular),
        where at least 70% of the code is JavaScript or TypeScript.
      </p>
    </form>
  )
}
