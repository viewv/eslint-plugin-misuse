# eslint-plugin-misuse

crypto misuse

## Installation

You'll first need to install [ESLint](https://eslint.org/):

```sh
npm i eslint --save-dev
```

Next, install `eslint-plugin-misuse`:

```sh
npm install eslint-plugin-misuse --save-dev
```

## Usage

Add `misuse` to the plugins section of your `.eslintrc` configuration file. You can omit the `eslint-plugin-` prefix:

```json
{
    "plugins": [
        "misuse"
    ]
}
```


Then configure the rules you want to use under the rules section.

```json
{
    "rules": {
        "misuse/rule-name": 2
    }
}
```

## Supported Rules

* Fill in provided rules here


