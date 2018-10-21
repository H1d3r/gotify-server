import CircularProgress from '@material-ui/core/CircularProgress';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import React, {Component} from 'react';
import {RouteComponentProps} from 'react-router';
import DefaultPage from '../component/DefaultPage';
import Message from '../component/Message';
import AppStore from '../stores/AppStore';
import MessagesStore from '../stores/MessagesStore';
import {observer} from 'mobx-react';
// @ts-ignore
import InfiniteAnyHeight from 'react-infinite-any-height';

interface IProps extends RouteComponentProps<{id: string}> {}

interface IState {
    appId: number;
}

@observer
class Messages extends Component<IProps, IState> {
    private static appId(props: IProps) {
        if (props === undefined) {
            return -1;
        }
        const {match} = props;
        return match.params.id !== undefined ? parseInt(match.params.id, 10) : -1;
    }

    public state = {appId: -1};

    private isLoadingMore = false;

    public componentWillReceiveProps(nextProps: IProps) {
        this.updateAllWithProps(nextProps);
    }

    public componentWillMount() {
        window.onscroll = () => {
            if (
                window.innerHeight + window.pageYOffset >=
                document.body.offsetHeight - window.innerHeight * 2
            ) {
                this.checkIfLoadMore();
            }
        };
        this.updateAll();
    }

    public render() {
        const {appId} = this.state;
        const messages = MessagesStore.get(appId);
        const hasMore = MessagesStore.canLoadMore(appId);
        const name = AppStore.getName(appId);
        const hasMessages = messages.length !== 0;

        return (
            <DefaultPage
                title={name}
                buttonTitle="Delete All"
                buttonId="delete-all"
                fButton={() => MessagesStore.removeByApp(appId)}
                buttonDisabled={!hasMessages}>
                {hasMessages ? (
                    <div style={{width: '100%'}} id="messages">
                        <InfiniteAnyHeight
                            key={appId}
                            list={messages.map(this.renderMessage)}
                            preloadAdditionalHeight={window.innerHeight * 2.5}
                            useWindowAsScrollContainer
                        />
                        {hasMore ? (
                            <Grid item xs={12} style={{textAlign: 'center'}}>
                                <CircularProgress size={100} />
                            </Grid>
                        ) : (
                            this.label("You've reached the end")
                        )}
                    </div>
                ) : (
                    this.label('No messages')
                )}
            </DefaultPage>
        );
    }

    private updateAllWithProps = (props: IProps) => {
        const appId = Messages.appId(props);

        this.setState({appId});
        if (!MessagesStore.exists(appId)) {
            MessagesStore.loadMore(appId);
        }
    };

    private updateAll = () => this.updateAllWithProps(this.props);

    private deleteMessage = (message: IMessage) => () => MessagesStore.removeSingle(message);

    private renderMessage = (message: IMessage) => {
        this.checkIfLoadMore();
        return (
            <Message
                key={message.id}
                fDelete={this.deleteMessage(message)}
                title={message.title}
                date={message.date}
                content={message.message}
                image={message.image}
            />
        );
    };

    private checkIfLoadMore() {
        const {appId} = this.state;
        if (!this.isLoadingMore && MessagesStore.canLoadMore(appId)) {
            this.isLoadingMore = true;
            MessagesStore.loadMore(appId).then(() => (this.isLoadingMore = false));
        }
    }

    private label = (text: string) => (
        <Grid item xs={12}>
            <Typography variant="caption" gutterBottom align="center">
                {text}
            </Typography>
        </Grid>
    );
}

export default Messages;