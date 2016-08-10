var Inbox = function () {

    var content = $('.inbox-content');
    var loading = $('.inbox-loading');

    var loadInbox = function (name) {
        var url = 'inbox_inbox.html';
        var title = $('.inbox-nav > li.' + name + ' a').attr('data-title');

        loading.show();
        content.html('');

        $.post(url, {}, function (res) {
            $('.inbox-nav > li.active').removeClass('active');
            $('.inbox-nav > li.' + name).addClass('active');
            $('.inbox-header > h1').text(title);

            loading.hide();
            content.html(res);
            App.fixContentHeight();
            App.initUniform();
        });
    }

    var loadMessage = function (name, resetMenu) {
        var url = 'inbox_view.html';

        loading.show();
        content.html('');

        $.post(url, {}, function (res) {
            if (resetMenu) {
                $('.inbox-nav > li.active').removeClass('active');
            }
            $('.inbox-header > h1').text('View Message');

            loading.hide();
            content.html(res);
            App.fixContentHeight();
            App.initUniform();
        });
    }

    var initTags = function (input) {
        input.tag({
            autosizedInput: true,
            containerClasses: 'span12',
            inputClasses: 'm-wrap',
            source: function (query, process) {
                return [
                    'Bob Nilson <bob.nilson@metronic.com>',
                    'Lisa Miller <lisa.miller@metronic.com>',
                    'Test <test@domain.com>',
                    'Dino <dino@demo.com>',
                    'Support <support@demo.com>']
            }
        });
    }

    var initWysihtml5 = function () {
        $('.inbox-wysihtml5').wysihtml5({
            "stylesheets": ["assets/plugins/bootstrap-wysihtml5/wysiwyg-color.css"]
        });
    }

    var initFileupload = function () {

        $('#fileupload').fileupload({
            // Uncomment the following to send cross-domain cookies:
            //xhrFields: {withCredentials: true},
            url: 'assets/plugins/jquery-file-upload/server/php/',
            autoUpload: true
        });

        // Upload server status check for browsers with CORS support:
        if ($.support.cors) {
            $.ajax({
                url: 'assets/plugins/jquery-file-upload/server/php/',
                type: 'HEAD'
            }).fail(function () {
                $('<span class="alert alert-error"/>')
                    .text('Upload server currently unavailable - ' +
                    new Date())
                    .appendTo('#fileupload');
            });
        }
    }

    var loadCompose = function () {
        var url = 'inbox_compose.html';

        loading.show();
        content.html('');

        // load the form via ajax
        $.post(url, {}, function (res) {
            $('.inbox-nav > li.active').removeClass('active');
            $('.inbox-header > h1').text('Compose');

            loading.hide();
            content.html(res);

            initTags($('[name="to"]'));
            initFileupload();
            initWysihtml5();

            $('.inbox-wysihtml5').focus();
            App.fixContentHeight();
            App.initUniform();
        });
    }

    var loadReply = function () {
        var url = 'inbox_reply.html';

        loading.show();
        content.html('');

        // load the form via ajax
        $.post(url, {}, function (res) {
            $('.inbox-nav > li.active').removeClass('active');
            $('.inbox-header > h1').text('Reply');

            loading.hide();
            content.html(res);
            $('[name="message"]').val($('#reply_email_content_body').html());

            initTags($('[name="to"]')); // init "TO" input field
            handleCCInput(); // init "CC" input field

            initFileupload();
            initWysihtml5();
            App.fixContentHeight();
            App.initUniform();
        });
    }

    var loadSearchResults = function () {
        var url = 'inbox_search_result.html';

        loading.show();
        content.html('');

        $.post(url, {}, function (res) {
            $('.inbox-nav > li.active').removeClass('active');
            $('.inbox-header > h1').text('Search');

            loading.hide();
            content.html(res);
            App.fixContentHeight();
            App.initUniform();
        });
    }

    var handleCCInput = function () {
        var the = $('.inbox-compose .mail-to .inbox-cc');
        var input = $('.inbox-compose .input-cc');
        the.hide();
        input.show();
        initTags($('[name="cc"]'), -10);
        $('.close', input).click(function () {
            input.hide();
            the.show();
        });
    }

    var handleBCCInput = function () {

        var the = $('.inbox-compose .mail-to .inbox-bcc');
        var input = $('.inbox-compose .input-bcc');
        the.hide();
        input.show();
        initTags($('[name="bcc"]'), -10);
        $('.close', input).click(function () {
            input.hide();
            the.show();
        });
    }

    return {
        //main function to initiate the module
        init: function () {

            // handle compose btn click
            $('.inbox .compose-btn a').live('click', function () {
                loadCompose();
            });

            // handle reply and forward button click
            $('.inbox .reply-btn').live('click', function () {
                loadReply();
            });

            // handle view message
            $('.inbox-content .view-message').live('click', function () {
                loadMessage();
            });

            // handle inbox listing
            $('.inbox-nav > li.inbox > a').click(function () {
                loadInbox('inbox');
            });

            // handle sent listing
            $('.inbox-nav > li.sent > a').click(function () {
                loadInbox('sent');
            });

            // handle draft listing
            $('.inbox-nav > li.draft > a').click(function () {
                loadInbox('draft');
            });

            // handle trash listing
            $('.inbox-nav > li.trash > a').click(function () {
                loadInbox('trash');
            });

            //handle compose/reply cc input toggle
            $('.inbox-compose .mail-to .inbox-cc').live('click', function () {
                handleCCInput();
            });

            //handle compose/reply bcc input toggle
            $('.inbox-compose .mail-to .inbox-bcc').live('click', function () {
                handleBCCInput();
            });

            //handle loading content based on URL parameter
            if (App.getURLParameter("a") === "view") {
                loadMessage();
            } else if (App.getURLParameter("a") === "compose") {
                loadCompose();
            } else {
                loadInbox('inbox');
            }

        }

    };

}();