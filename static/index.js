let mode = "ecb"
let size = "16"

function get_mode() {
    mode = event.target.value
}

function get_key_size() {
    size = event.target.value
}

function get_file() {
    const file = document.getElementById("file")
    const txt = document.getElementById("file__name")

    file.click()

    file.addEventListener("change", function () {
        let fullpath = file.value
        if (fullpath) {
            let startIndex = (fullpath.indexOf("\\") >= 0 ? fullpath.lastIndexOf("\\") : fullpath.lastIndexOf("/"))
            let filename = fullpath.substring(startIndex)
            if (filename.indexOf("\\" === 0) || filename.indexOf("/") === 0) {
                filename = filename.substring(1)
            }
            if (filename.length < 20) {
                txt.innerHTML = filename
            } else {
                txt.innerHTML = filename.substring(0, 20) + "..."
            }
        } else {
            txt.innerHTML = "Выберите файл"
        }
    })
}

function communicate() {
    let xhr = new XMLHttpRequest();
    let res = document.getElementById("res")
    let btn = document.getElementById("but")

    res.innerHTML = ""
    btn.disabled = true

    let form = new FormData();
    message = document.getElementById("file")

    if (!message.value) {
        res.innerHTML = ""
        return
    }

    form.append("file", message.files[0])
    form.append("key", document.getElementById("key").value)
    form.append("c0", document.getElementById("c0").value)
    form.append("key_size", size)
    form.append("mode", mode)
    form.append("decode", document.getElementById("checkbox").checked)

    xhr.open("POST", "http://127.0.0.1:5000/rc6")
    xhr.send(form)

    let source = new EventSource("/progress-status")
    get_progress(source)

    xhr.onload = function () {
        source.close()
        js = JSON.parse(xhr.response)
        if (js["path"] == undefined) {
            res.innerHTML = js["error"]
        } else {
            res.innerHTML = `<a class="file__link" href="${js["path"]}">Скачать</a>`
        }
        btn.disabled = false
    }
}

function get_progress(source) {
    source.onmessage = function (event) {
        var elem = document.getElementById("res");
        elem.innerHTML = JSON.parse(event.data).progress + "%";
        if (JSON.parse(event.data).progress == 99) {
            source.close()
        }
    }
}